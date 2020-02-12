# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# March 31 2015, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2015, Deutsche Telekom AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
import copy
import logging
from lxml import etree
from netconf import NSMAP, qmap
from netconf import error

# Tries to somewhat implement RFC6241 filtering
logger = logging.getLogger(__name__)


def qname(tag):
    """Return a qualified tag name (i.e. {namespace}localtag)

    Handles prefix notation by looking up in global dictionary.

    :param tag: A possibly prefixed tag.
    :returns: Fully qualified tag name (`lxml.etree.QName`).
    """
    try:
        return etree.QName(tag)
    except ValueError:
        prefix, base = tag.split(":")
        return etree.QName(NSMAP[prefix], base)


def elm(tag, attrib=None, **extra):
    """Create an `lxml.etree.Element` using `qname` to obtain the tag.

    This is a replacement for calling `lxml.etree.Element` directly that
    supports prefixed tags.

    :param tag: A possibly prefixed tag.
    :param attrib: Attributes for the element.
    :param extra: extra parameters see `lxml.etree.Element`.
    :returns: `lxml.etree.Element`.
    """
    if attrib is None:
        attrib = dict()
    return etree.Element(qname(tag), attrib, **extra)


def leaf_elm(tag, value, attrib=None, **extra):
    """Create an `lxml.etree.Element` leaf node using `qname` to obtain the tag.

    This is a replacement for calling `lxml.etree.Element` directly that supports
    prefixed tags.

    :param tag: A possibly prefixed tag.
    :param value: Value for text of element.
    :param attrib: Attributes for the element.
    :param extra: extra parameters see `lxml.etree.Element`.
    :returns: `lxml.etree.Element`.
    """
    e = elm(tag, attrib, **extra)
    e.text = str(value)
    return e


# Create another name for leaf_elm function
leaf = leaf_elm


def subelm(pelm, tag, attrib=None, **extra):
    """Create an child `lxml.etree.Element` using `qname` to obtain the tag.

    This is a replacement for calling `lxml.etree.SubElement` directly that
    supports prefixed tags.

    :param pelm: The parent element.
    :param tag: A possibly prefixed tag.
    :param attrib: Attributes for the element.
    :param extra: extra parameters see `lxml.etree.SubElement`.
    :returns: `lxml.etree.Element`.
    """
    if attrib is None:
        attrib = dict()
    return etree.SubElement(pelm, qname(tag), attrib, **extra)


def is_selection_node(felm):
    ftext = felm.text
    return ftext is None or not ftext.strip()


def xpath_filter_result(data, xpath):
    """Filter a result given an xpath expression.

    :param data: The nc:data result element.
    :param xpath: The xpath expression string.
    :returns: New nc:data result element pruned by the xpath expression.

    >>> xml = '''
    ... <data>
    ...   <devs>
    ...     <dev>
    ...       <name>dev1</name>
    ...       <slots>1</slots>
    ...     </dev>
    ...     <dev>
    ...       <name>dev2</name>
    ...       <slots>2</slots>
    ...     </dev>
    ...     <dev>
    ...       <name>dev3</name>
    ...       <slots>3</slots>
    ...     </dev>
    ...   </devs>
    ... </data>
    ... '''
    >>> data = etree.fromstring(xml.replace(' ', '').replace('\\n', ''))
    >>> result = xpath_filter_result(data, "/devs/dev")
    >>> etree.tounicode(result)
    '<data><devs><dev><name>dev1</name><slots>1</slots></dev><dev><name>dev2</name><slots>2</slots></dev><dev><name>dev3</name><slots>3</slots></dev></devs></data>'
    >>> result = xpath_filter_result(data, "/devs/dev[name='dev1']")
    >>> etree.tounicode(result)
    '<data><devs><dev><name>dev1</name><slots>1</slots></dev></devs></data>'
    >>> result = xpath_filter_result(data, "/devs/dev[name='dev2']")
    >>> etree.tounicode(result)
    '<data><devs><dev><name>dev2</name><slots>2</slots></dev></devs></data>'
    >>> result = xpath_filter_result(data, "/devs/dev[name='dev2'] | /devs/dev[name='dev1']")
    >>> etree.tounicode(result)
    '<data><devs><dev><name>dev1</name><slots>1</slots></dev><dev><name>dev2</name><slots>2</slots></dev></devs></data>'
    >>> result = xpath_filter_result(data, "/devs/dev[name='dev1'] | /devs/dev[name='dev2']")
    >>> etree.tounicode(result)
    '<data><devs><dev><name>dev1</name><slots>1</slots></dev><dev><name>dev2</name><slots>2</slots></dev></devs></data>'
    >>> result = xpath_filter_result(data, "/devs/dev[name='dev1'] | /devs/dev[slots='2']")
    >>> etree.tounicode(result)
    '<data><devs><dev><name>dev1</name><slots>1</slots></dev><dev><name>dev2</name><slots>2</slots></dev></devs></data>'
    """

    # First get a copy we can safely modify.
    data = copy.deepcopy(data)

    results = []
    children = []

    # XXX Need to reset the namespace declarations to those found in the context of the filter node.

    # Have to re-root the children to avoid having to match "/nc:data"
    for child in data.getchildren():
        data.remove(child)
        children.append(child)
        newtree = etree.ElementTree(child)
        results.extend(newtree.xpath(xpath, namespaces=NSMAP))

    # Add the children of data back.
    for child in children:
        data.append(child)

    # Mark the tree up
    for result in results:
        # Mark all children
        for e in result.iterdescendants():
            e.attrib['__filter_marked__'] = ""
        # Mark this element and all parents
        while result is not data:
            result.attrib['__filter_marked__'] = ""
            result = result.getparent()

    def prunedecendants(e):
        for child in e.getchildren():
            if '__filter_marked__' not in child.attrib:
                e.remove(child)
            else:
                prunedecendants(child)
                del child.attrib['__filter_marked__']

    prunedecendants(data)

    return data


def _get_xpath_tag(nsmap, ns, child):
    del ns
    ctag = qname(child.tag)
    ns = _ns2prefix(nsmap, ctag.namespace)
    if ns == "*":
        return "*[local-name()='{}']".format(ctag.localname), ns
    else:
        return "{}:{}".format(ns, ctag.localname), ns


def _get_xpath_tag_if_inheritance_worked(nsmap, ns, child):
    ctag = qname(child.tag)
    if ((ns != "*" and ctag.namespace == nsmap[ns]) or (ns == "*" and not ctag.namespace)):
        tag = "{tag}".format(tag=ctag.localname)
    else:
        ns = _ns2prefix(nsmap, ctag.namespace)
        tag = "{ns}:{tag}".format(ns=ns, tag=ctag.localname)
    return tag, ns


def _linearize(el, ns, path):

    mpaths = []
    select_count = 0

    # Get match criteria
    for child in el:
        if len(child) > 0:
            # This should be a user friendly error
            # assert not child.text
            select_count += 1
        elif child.text and child.text.strip():
            tag, _ = _get_xpath_tag(NSMAP, ns, child)
            ctext = child.text.strip().replace("'", r"\'")
            mpaths.append("{}='{}'".format(tag, ctext))
        else:
            select_count += 1

    if mpaths:
        path += "[" + " or ".join(mpaths) + "]"
        if not select_count:
            # If we only have match nodes then return the contained that match
            yield path
            return

    for child in el:
        tag, newns = _get_xpath_tag(NSMAP, ns, child)
        if len(child) > 0:
            text = '{path}/{tag}'.format(path=path, tag=tag)
            for x in _linearize(child, newns, text):
                yield x
        else:
            text = '/{tag}'.format(tag=tag)
            yield path + text


def _ns2prefix(nsmap, namespace):
    if not namespace:
        return "*"

    for prefix, ns in nsmap.items():
        if namespace is None:
            return prefix
        if ns == namespace:
            return prefix
    # This is an error
    assert False


def filter_to_xpath(felm):
    """Convert a filter sub-tree to an xpath expression.

    :param felm: A subtree-filter XML sub-tree.
    :returns str: An xpath expression equivalent to the sub-tree.
    """
    root = felm[0]
    rtag = qname(root.tag)
    ns = _ns2prefix(root.nsmap, rtag.namespace)
    xpaths = []
    root_xpath = _get_xpath_tag(NSMAP, None, root)[0]
    for path in _linearize(root, ns, "/{}".format(root_xpath)):
        xpaths.append(path)

    result = ' | '.join(xpaths)
    return result


def filter_results(rpc, data, filter_or_none, debug=False):
    """Check for a user filter and prune the result data accordingly.

    :param rpc: An RPC message element.
    :param data: The data to filter.
    :param filter_or_none: Filter element or None.
    :type filter_or_none: `lxml.Element`
    """
    if filter_or_none is None:
        return data

    type_attr_name = qmap("nc") + "type"
    select_attr_name = qmap("nc") + "select"

    if type_attr_name not in filter_or_none.attrib or filter_or_none.attrib[
            type_attr_name] == "subtree":
        # Check for the pathalogical case of empty filter since that's easy to implement.
        if not filter_or_none.getchildren():
            return elm("nc:data")

        xpf = filter_to_xpath(filter_or_none)

    elif filter_or_none.attrib[type_attr_name] == "xpath":
        if select_attr_name not in filter_or_none.attrib:
            raise error.MissingAttributeProtoError(rpc, filter_or_none, select_attr_name)
        xpf = filter_or_none.attrib[select_attr_name]
    else:
        msg = "unexpected type: " + str(filter_or_none.attrib[type_attr_name])
        raise error.BadAttributeProtoError(rpc, filter_or_none, type_attr_name, message=msg)

    logger.debug("Filtering on xpath expression: %s", str(xpf))
    return xpath_filter_result(data, xpf)


def filter_tag_match(filter_tag, elm_tag):
    fqname = etree.QName(filter_tag)
    eqname = qname(elm_tag)
    if not fqname.namespace:
        return fqname.localname == eqname.localname
    return fqname == eqname


def filter_node_match_no_value(filter_node, match_elm):
    # First check to see if tag matches.
    if not filter_tag_match(filter_node.tag, match_elm.tag):
        return False

    # Next check for attribute matches.
    # XXX does this need to filter out namespace attributes?
    if filter_node.attrib and filter_node.attrib != match_elm.attrib:
        return False

    return True


def filter_node_match(filter_node, match_elm):
    """Given a filter node element and a nodename and attribute dictionary
    return true if the filter element matches the elmname, attributes and value
    (if not None).

    The filter element can use a wildcard namespace or a specific namespace
    the attributes can be missing from the filter node but otherwise must match
    and the value is only checked for a match if it is not None.
    """
    if not filter_node_match_no_value(filter_node, match_elm):
        return False

    # Finally check for matching value.
    ftext = filter_node.text
    if ftext is None:
        return True

    ftext = ftext.strip()
    if not ftext:
        return True

    return ftext == match_elm.text


def filter_leaf_values(fcontain_elm, dest_node, leaf_elms, append_to):
    """Given a containment element (or None) verify that all leaf elements
    in leaf_elms either match, have corresponding selection nodes (empty)
    or are not present.

    Additionally the correct leaf data will be added to dest_node, and dest_node
    will be appended to append_to if append_to is not None.

    The return value with be True, False, or a possibly empty set of selection/containment nodes
    The only failing value is False, if True is returned then the caller should include all
    containment sibling nodes, otherwise the caller should process the list of containment/selection
    nodes.
    """
    children = fcontain_elm.getchildren() if fcontain_elm is not None else []
    selected_elms = []
    if not children:
        selected_elms = leaf_elms

    # Now look at all the leaf filter selector or match nodes
    include_all_leaves = True
    othernodes = []
    for felm in children:
        fchildren = felm.getchildren()
        for lelm in leaf_elms:
            if fchildren:
                # Verify that this doesn't match a leaf node.
                if filter_node_match_no_value(felm, lelm):
                    # XXX this is an error we should raise some exception.
                    return False
                continue
            elif filter_node_match(felm, lelm):
                if not felm.text:
                    # This was a selection node.
                    include_all_leaves = False

                selected_elms.append(lelm)
                break
        else:
            if fchildren:
                # This is OK we verified a containment filter didn't match leaf by getting here.
                if felm.text:
                    # XXX verify that there is no text on this node, report violation?
                    return False

                # Track selection/filter nodes
                include_all_leaves = False
                othernodes.append(felm)
            elif not felm.text:
                # This is OK as it means this is a selection node include it in othernodes
                include_all_leaves = False
                othernodes.append(felm)
            else:
                # We've exhausted all leaf elements to match this leaf filter so we failed.
                return False

    # Everything matched so add in the leaf data.
    if append_to is not None:
        append_to.append(dest_node)

    if include_all_leaves:
        dest_node.extend(leaf_elms)
    else:
        dest_node.extend(selected_elms)

    if include_all_leaves:
        return True
    return othernodes


def filter_containment_iter(fcontain_elm, dest_node, containment_nodes, leaf_elms, append_to):
    """Given a containment filter node (or None) verify that all leaf elements
    either match, have corresponding selection nodes (empty) or are not present.

    If all leaf criteria are met then the iterator will return a triple of
    (new_filter_node, new_dest_node, new_data). new_filter_node corresponds to the
    matched containment node which is returned in new_dest_node, and new_data will be
    an element corresponding to the passed in dest_node.

    These should be processed by calling filter_containment_iter again.

    Additionally the correct leaf data will be added to dest_node, and dest_node
    will be appended to append_to if append_to is not None.

    This implements RFC6241 section 6.2.5
    """
    # No containment node so add everything.
    if fcontain_elm is None:
        # Add in the leaf data
        for e in leaf_elms:
            dest_node.append(e)

        # Append the match_node to the data
        if append_to is not None:
            append_to.append(dest_node)

        for node in containment_nodes:
            yield None, copy.copy(node), dest_node

    else:
        othernodes = filter_leaf_values(fcontain_elm, dest_node, leaf_elms, append_to)
        if othernodes is False:
            # No match
            pass
        elif othernodes is True:
            # All leaf values have matched and have been added and we should include all containers
            for node in containment_nodes:
                yield None, copy.copy(node), dest_node
        else:
            for felm in othernodes:
                for node in containment_nodes:
                    if filter_node_match_no_value(felm, node):
                        yield felm, copy.copy(node), dest_node


def filter_leaf_allows_add(filter_elm, tag, data, value):
    if filter_leaf_allows(filter_elm, tag, value):
        data.append(leaf_elm(tag, value))
        return True
    return False


def filter_leaf_allows(filter_elm, xpath, value):
    """Check the value at the xpath specified leaf matches the value.

    - If filter_elm is None then allow.
    - If there is no xpath element then allow if there are no other children.
    - XXX what about xpath that has embedded predicates!
      perhaps what we want to call this is a normal path not an xpath.
    """
    if filter_elm is None:
        return True

    # If there are no children then allow everything.
    if not filter_elm.getchildren():
        return True

    # No match or multiple matches not allowed for leaf.
    flist = filter_elm.xpath(xpath, namespaces=NSMAP)
    if not flist or len(flist) > 1:
        return False
    felm = flist[0]

    # No children for leaf allowed (leaf)
    if felm.getchildren():
        return False

    # Allowed if empty or if value matches.
    if not felm.text or felm.text == str(value):
        return True

    return False


def filter_list_iter(filter_list, key_xpath, keys):
    """Return key, elm pairs that are allowed by keys using the values found using
    the given key_xpath"""
    # If we have no filter elm then return all keys.
    if filter_list is None:
        for key in keys:
            yield key, None

    try:
        # If this an element then make it a list of elements
        filter_list.xpath  # pylint: disable=W0104
        filter_list = [filter_list]
    except AttributeError:
        pass

    for filter_elm in filter_list:
        filter_elms = [x for x in filter_elm.xpath(key_xpath, namespaces=NSMAP)]
        filter_keys = [x.text for x in filter_elms]
        if not filter_keys:
            for key in keys:
                yield key, filter_elm
        else:
            # Now walk our keys returning any that are in the filter list.
            for key in keys:
                if key in filter_keys:
                    yield key, filter_elm
                # try:
                #     idx = filter_keys.index(str(key))
                #     yield key, filter_elm
                # except ValueError:
                #     pass


__author__ = 'Christian Hopps'
__date__ = 'March 31 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
