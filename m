Return-Path: <kasan-dev+bncBC24VNFHTMIBBZU4YLUAKGQE7OK44BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 57E96504D5
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 10:48:39 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id i196sf15401180qke.20
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 01:48:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561366118; cv=pass;
        d=google.com; s=arc-20160816;
        b=AN0uA91RLUu/n/LyQxdolLkgnovnP1H/Uyk2lcIAKShkVaROxTFuqk2FkZn6xNW6XQ
         lP+r208P9I5ak0zpdy/ymbDhSpELlO26XO5nNPuIeGm7zhUIrlkQlkbt+nUGzyredVEu
         P/6Auf2eysLRrLUgEpgVkbowf251JcpVlEjRKlQKQ6H+AThM0fdfxQxaqtFoY+ZY/2Xs
         xULV3usRtnBMm6zGKkuncsEvdiPDWVd2a5npGziNhrIrONXoTPd6HT8/1p1X8pfCjGlD
         yBUvoU2KVLKjZu6xaqLL81ihvbxupnJNeR8fdboQruQz0hV4Eh5uVaLxfzfpDdjxVvK8
         kj5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Pg862OC40zhnKaKPl9XDGHCtmmiD8S9nCwjQ23Y39Eg=;
        b=x8MFYQ9sDCuYAD7CF59RNN+BE4Mgcg1T/bEmYpQX9/9raJRGdpc5hR2wMyOKvU2lCC
         VrHi92dJ098Fp5KZEF8ye6GHaHYNrZEUa2nPqdWJ4TkgM0/MTX9cKzpp163bSaxJB+xQ
         kJAn/aB9Ll8Z6NEe83YITwyPNjjpyjvJ6YudD8xrdb2QTixIz6pqVDOxeorfP16eGFFN
         2nUrfTXB2Lzm4gXkwlNBmStzuUjpuro2sZTiu3MeLH6+jnl8ryzyTPDwpZanUs0e5138
         aYMZxeFY+LEVHYvPfIGlhZwqIC4lgIWosWldXQB2NHwFN90qY2RPXU13HQjM6rSBsHGM
         As0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pg862OC40zhnKaKPl9XDGHCtmmiD8S9nCwjQ23Y39Eg=;
        b=A95pkCp6eGQlFF4IJ26nr6tVM0n2PNu4gTbKVGz/cq42w9BMRFnp+xjgeXttSC+91C
         YbutCDAauLjiBfSPtAqhV8OLkMdPJrXHkbz3hkFbJjYX86qbjKtlUB5v/IwfcMo/nlej
         HegcKe9LwCWTkG70kK9JzZuqsyYwmkm+r31AgAvy1ewwNpZWP3aRtn1oAtug1r1Uwsjy
         DFi3/486Qzk9mrMDgxbPSmp97yOABQraPHBS+tqgQT1hPy1IlilufD6cIZmGfcXPEoRD
         C4gcfdtFKjX28CfUvwzaNejGOAHsHLCCBuRZTsQQ3SKSAe1ZMPPoiuxbl2IzaSHd5EJW
         L3RQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pg862OC40zhnKaKPl9XDGHCtmmiD8S9nCwjQ23Y39Eg=;
        b=ppXQvh8s0rBJ7A5quttMClmGm1JAut3SROkBWBPrE+35oz21F/xornRp8RiDKra7jE
         0m+hJlLBYNMeuD6BDTeenm/VVRyMJpNpiDhLFusxi196p32mR1NlAXmb1PJt+wHCWrWx
         57v7PSCwHtBcoFtWrelO23RaiJA9mRXGeGgvx0PRzp8eV1p0F2jJZMry1Y2r63O7dB6m
         KrBBzxHSavJunf6BehNfSPt1y7827Hrv6GKrDesfNSuqvuokFGp0Ow3sEXNWq4JgiFnq
         4HJWeuk22XhLVAJS/B2KYAf9/H/kLalVk84clFCzxJTo1e5ZCAzy66P625cOPvD/wkPk
         oM/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXBnbNh+xxdPxSpM/aYzMnoykvY7QfgnkbXbvHKIFRtBS6JsMyL
	AIE0hU1G+gLpx0/RG6FY77I=
X-Google-Smtp-Source: APXvYqyVfV1vEOmZeEnY9tZ8PU44hB9C8ckRjtZJE811BhX4WtWT9tyjCsXn/rAEZzrtLxen5W8ODg==
X-Received: by 2002:a37:488c:: with SMTP id v134mr4642366qka.276.1561366118285;
        Mon, 24 Jun 2019 01:48:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:818:: with SMTP id u24ls456772qth.5.gmail; Mon, 24 Jun
 2019 01:48:38 -0700 (PDT)
X-Received: by 2002:ac8:431e:: with SMTP id z30mr128432014qtm.291.1561366118051;
        Mon, 24 Jun 2019 01:48:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561366118; cv=none;
        d=google.com; s=arc-20160816;
        b=mVv0cIgGT8mmVsa0ywlJlLaXazG5MZIlW8WEslABawJA6fWC3QomPyig/UZDgbPLMH
         l/j9Q2zGzHxiQbAQpwS46bmDwlDYB1uQCGm/a2udBDBOZ90MWmZylVvannkk9I8tGddi
         7opCPJkQ8zHCiZbZINFzSFCLN1pnJY7uWaiCYMqa+nxuggv0MosloUBYJOHGYqqjz1qC
         8OPy76L0Rmlz5qI3XyFLNf8sacpjrnFYj9S7AFBqGeoTNM0ZnoSssSzCQE7lzmHo/Wjw
         pQ3BsbjVK6GQXJ7vmA3SDBkJDRFbhRPEP066uuJ7MZzIFOzgvGv4Lc93EvnAozpA4bCm
         tRxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=N6eX85eDIllUe4PCBiG1+up8TbwkKVYGQFFHS4SlSKs=;
        b=lOkvk/Vi1aZ6wa9R7YnipLwLTzx0U8n1aRgKgZtczyVUv4jxOrx5ynEgi6Nu8HiOX9
         nTVkaFxvuWEll5zxCfvZvjYuow7kfCB3V0eiQH5qBwo3dlBP83qDjeDjaKogZ6wVtnos
         cHhizonmBlWCRa9wcXXRJh1QEDouo4/phAHoQ1kO3RMYSAgR0HfU0PYLsR53k3p5gagq
         p9ll4hwbKrA9wnxalDTDtl3ZigT5hhjakwTFSUvOPZNXg72mPZI/0HlKmKNbSSC4bmIG
         /bUm5SQ/qKBloevJzBbnz8DS30pQcksEOD0EOpyJMy8lYHqzYV3iEK8Es5Wxt0h3Vvfd
         Tpzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id a79si792309qkb.1.2019.06.24.01.48.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jun 2019 01:48:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id DFC4128B7B
	for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2019 08:48:36 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id CE44E28B85; Mon, 24 Jun 2019 08:48:36 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203967] New: KASAN: incorrect alloc/free stacks for alloc_pages
 memory
Date: Mon, 24 Jun 2019 08:48:36 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-203967-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

https://bugzilla.kernel.org/show_bug.cgi?id=203967

            Bug ID: 203967
           Summary: KASAN: incorrect alloc/free stacks for alloc_pages
                    memory
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: enhancement
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Example of a bug report:
https://syzkaller.appspot.com/bug?extid=372f5b98ac3765e3a314
https://groups.google.com/forum/#!msg/syzkaller-upstream-moderation/hdpFfR_MfmY/djyDOB86BgAJ
KASAN report is also copied below for convenience.

There is a large 8160-byte access that presumably overflows an
alloc_pages-allocated page. It seems there are several problems here:
1. alloc_pages-allocated pages don't have redzones, we take alloc/free stacks
and page info for the "first bad byte", which is different and most likely
irrelevant page. In case of a memset overflow, we could use the original page
instead (memset base).
2. We don't memorize alloc/free stacks for page allocator. We should.

Addressing both of these things would result in a much more useful report: we
would say where the original page starts, size of compound page, provide alloc
and free stacks for it.

================================================================== 
BUG: KASAN: use-after-free in memset include/linux/string.h:344 [inline] 
BUG: KASAN: use-after-free in __ext4_expand_extra_isize+0x16c/0x240   
fs/ext4/inode.c:5930 
Write of size 8160 at addr ffff888061f844a0 by task syz-executor.2/19044 

CPU: 1 PID: 19044 Comm: syz-executor.2 Not tainted 5.2.0-rc4-next-20190614   
#15 
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS   
Google 01/01/2011 
Call Trace: 
  __dump_stack lib/dump_stack.c:77 [inline] 
  dump_stack+0x172/0x1f0 lib/dump_stack.c:113 
  print_address_description.cold+0xd4/0x306 mm/kasan/report.c:351 
  __kasan_report.cold+0x1b/0x36 mm/kasan/report.c:482 
  kasan_report+0x12/0x20 mm/kasan/common.c:614 
  check_memory_region_inline mm/kasan/generic.c:185 [inline] 
  check_memory_region+0x123/0x190 mm/kasan/generic.c:191 
  memset+0x24/0x40 mm/kasan/common.c:107 
  memset include/linux/string.h:344 [inline] 
  __ext4_expand_extra_isize+0x16c/0x240 fs/ext4/inode.c:5930 
  ext4_try_to_expand_extra_isize fs/ext4/inode.c:5982 [inline] 
  ext4_mark_inode_dirty+0x6e7/0x940 fs/ext4/inode.c:6058 
  ext4_dirty_inode+0x8f/0xc0 fs/ext4/inode.c:6092 
  __mark_inode_dirty+0x915/0x1280 fs/fs-writeback.c:2161 
  generic_update_time+0x21c/0x370 fs/inode.c:1664 
  update_time fs/inode.c:1680 [inline] 
  touch_atime+0x23c/0x2a0 fs/inode.c:1751 
  file_accessed include/linux/fs.h:2175 [inline] 
  iterate_dir+0x36d/0x5e0 fs/readdir.c:56 
  __do_sys_getdents fs/readdir.c:231 [inline] 
  __se_sys_getdents fs/readdir.c:212 [inline] 
  __x64_sys_getdents+0x226/0x3c0 fs/readdir.c:212 
  do_syscall_64+0xfd/0x680 arch/x86/entry/common.c:301 
  entry_SYSCALL_64_after_hwframe+0x49/0xbe 
RIP: 0033:0x45761b 
Code: 02 74 b6 31 f6 eb b9 0f 1f 84 00 00 00 00 00 41 57 41 56 48 63 ff 41   
55 41 54 b8 4e 00 00 00 55 53 48 89 f3 48 83 ec 08 0f 05 <48> 3d 00 f0 ff   
ff 77 55 4c 8d 24 06 49 89 c5 4c 39 e6 73 33 90 0f 
RSP: 002b:00007fff60de2ce0 EFLAGS: 00000202 ORIG_RAX: 000000000000004e 
RAX: ffffffffffffffda RBX: 0000555556115970 RCX: 000000000045761b 
RDX: 0000000000008000 RSI: 0000555556115970 RDI: 0000000000000003 
RBP: 0000555556115970 R08: 0000000000000001 R09: 0000555556114940 
R10: 0000000000000000 R11: 0000000000000202 R12: ffffffffffffffd4 
R13: 0000000000000016 R14: 0000000000000000 R15: 00007fff60de3e80 

The buggy address belongs to the page: 
page:ffffea000187e100 refcount:2 mapcount:0 mapping:ffff8880a10e3558   
index:0x453 
def_blk_aops 
flags: 0x1fffc000000203a(referenced|dirty|lru|active|private) 
raw: 01fffc000000203a ffffea0001fe6488 ffffea0001d8ae48 ffff8880a10e3558 
raw: 0000000000000453 ffff888094c2cf18 00000002ffffffff ffff88805ca5aac0 
page dumped because: kasan: bad access detected 
page->mem_cgroup:ffff88805ca5aac0 

Memory state around the buggy address: 
  ffff888061f85f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
  ffff888061f85f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
> ffff888061f86000: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
                    ^ 
  ffff888061f86080: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
  ffff888061f86100: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
==================================================================

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203967-199747%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
