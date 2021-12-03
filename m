Return-Path: <kasan-dev+bncBC24VNFHTMIBB3XIU6GQMGQETQ3N6WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id EFDC9467548
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 11:41:50 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id q15-20020adfbb8f000000b00191d3d89d09sf517479wrg.3
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 02:41:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638528110; cv=pass;
        d=google.com; s=arc-20160816;
        b=qpL2L1xo/wsSwkEF6HsqtKLEBfYQknsnwZ+h3NgsHqHzwsZkd7fJKLmwuA3+caD23O
         nJAonHl9npUG4w0hMmjqLwWgR/oy3qj6IimyMq7ZhpGGV/vnQtNXnluF80S7LreP//zC
         laEVdEKmrTSMXcTRvjB8MjEykzbjtnUMjkJxxDGvyOK/6Jp9K052kEDr2JK+PwGv/5mZ
         tkWqNx8rUJPoxG92A2mIcifPAFb8ttw22AHUqOktjr+uiVK+driQkv1fQPtCGd2Rwjr2
         GT00l2/LFrSUwiOfqkOh+UiYsATOW3DA7IXvdga+gOXZt+inMo5fRacFdqg8tt7vfh+H
         JYdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=dOmuNk7zalbLJI9lEHzM0jIO7jAHFNBido3FIu9pBsk=;
        b=qF1Y96IHQoufn1uuLKuls9Xt3N95T7CPrw5+yeD38bDzpbBKXxEYJtRRkuWIZ+Rp55
         o0p9RZgoCLvFTzgQL/+TjharyUf7P8x12chq1HT29mefrHfQ7DK3rAEHfsIfHuZ5tMYu
         EyV2lPiTBfbwTDpGWaZ2lPiu60XEJSNDuvLuDKlVwOjA34InQG9KNLD4eOFHwnJ+Ib1B
         LPSRWMXm2npK+xzW4bMY/whHHA5U+xPYgU+F8Q3bsNXofF3A9HwJzwFimfZia/GwqzYC
         5i8SU/zGfGqz3twnPbj/u6YTLUEsqENaBUpuTwu+cuaJvo1uQJ7mzwKtzRvO7jaIV7bQ
         bcQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UGyt6c7B;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dOmuNk7zalbLJI9lEHzM0jIO7jAHFNBido3FIu9pBsk=;
        b=WMH4wntN1ziOp9lvdpEn2x9+0lAGD5I0AGinFriYgIk1lHNmfpe/K2nvCxG3Wurhk+
         vRq1ijFy90qHW2zOlsfL6J4gnkTyVVYqEDzKGwDiAwfLA0GYf9LDovPDB8mnXmBNJ8DA
         1p165KU4Hsb0osdS2Ue129KJiQQGBlVuVs2JwfF96oLnp6TMrYal6ZcM6qlTFSRTb9zk
         OdNNc1RSYqtSbI0g8pPxVWLaMUbMn0fsjGle+Jh8uH8lRBpW9+vXgO4jZSaSJ7Af0GCD
         LuTt4EuMCARVKOiZ9K5oIy+9FB74z/ehptFy9nVH1ETV9+kg26i0CcmVP4EnpYqDxBFP
         BDVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dOmuNk7zalbLJI9lEHzM0jIO7jAHFNBido3FIu9pBsk=;
        b=PAE/T2pfVBL4zQC98BvC6/BlJ0Hnmwfl29vCBypuFDl4yP90Px1maDJLn9ffVFDplF
         MYfIRHXAmTtl0DUU8ZlRPLgsd/MQTcHH6P59fmusnuQtQt1Fvu2hsRiL1qrDffgWh8nh
         oC7wQtjd9cRmZQ4/TckAxwT2/rRZ4vKP8bsLCTT09LaRBWDab1yPDGwn+JL+fO6J20xV
         13XLPIGHELyMMI+fUPbKqUMETalcYUk8tCUmFAcxXDghvtrTkGe9CZJrjL3yRpiy5CYk
         FE8hNcBOyPFIydC2xsGdvaPpfBzGLfVKV/4mq3OF+GZltlN8X+uEczwrTYMIj0//8gxH
         tsgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531eLZekMu9XlKYYqjLcLgdmle8ZCdOG8JboyPW3+bboLTAnyNVW
	CmdWAD6DwZpra4gDKuqlH+0=
X-Google-Smtp-Source: ABdhPJz4EAbHmNdyg7XsRMEu+wR6Cg19sGQ+zLRZi945j1yeszG1bvsAh1+X1aszXa5Wb3RdYopVCQ==
X-Received: by 2002:adf:ea90:: with SMTP id s16mr20592307wrm.288.1638528110693;
        Fri, 03 Dec 2021 02:41:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:ad6:: with SMTP id c22ls6512440wmr.1.canary-gmail;
 Fri, 03 Dec 2021 02:41:49 -0800 (PST)
X-Received: by 2002:a05:600c:2195:: with SMTP id e21mr14276737wme.187.1638528109870;
        Fri, 03 Dec 2021 02:41:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638528109; cv=none;
        d=google.com; s=arc-20160816;
        b=EC+qft/hxW93rJwlN41DOvAE0JOhiE5lA0f/aqNM7iQoMZKRmvsCuo/ao0iO0XGLAX
         cgbhln6Qj2HK0nIUMYEdLkE/UcDVDnC+rlDVdfWbsd+Lk2rkyF9/mCP9OQ0KGTSGBhBR
         +dJW80w+wdfZ1jMON+BDtTEZVSKOZfR/2cJy7Sm0Sjr6RBdfhkea0FdIjMOLzTc1JQ41
         0/rSPEZE7/GkniOyfClPBedMRuhBdWUZ6JN9RxqDs8EMK1uyCso1XvOJd5zGmCNREAsU
         +Rd5w+WgcEcNgoeXKaHJy6UP3tcJuW/IEBzOrkq8ggcCwFk7+vGuAxCNxdx1wIoKS0Sr
         6GQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=XWmg9Yg2azJsu5XdHmKH0qHibFR+4A0hYCTkTKq879E=;
        b=Yy+HdvtRU7scrEC1CUQANIitHKmiXr53bnmgfPbb6NPWN8RKiMIalSXJIqXT4fzTV6
         YDsbiYkt1E1W8KtrgrqXtiDznG65iYkPVIvqIJKQ+7rxgjAvlClWrYO2Q2AvDx7a+d+I
         tP81ZUZVlvIYr6MrkSl2s4VZO4DO1GxzWBMgA538SYyj9+W5YIrmncMUoPKQJnM+A168
         hyrZ46Zi7keHO2tQxGHpqSnv23pFgqg49fD3Dv3zUJ04Yas12CZCQmnPVunrxYUTvlid
         XX32bsxo/EdEiiIANVNxDmCtca5oSu6n4LXVQtVZ1Pfon/CJbQqj6cbnlXtZLeZtq9/H
         t4Ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UGyt6c7B;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id o19si361727wme.2.2021.12.03.02.41.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Dec 2021 02:41:49 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 6ADF9B82604
	for <kasan-dev@googlegroups.com>; Fri,  3 Dec 2021 10:41:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 1DC29C53FC7
	for <kasan-dev@googlegroups.com>; Fri,  3 Dec 2021 10:41:46 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 0930C60FF4; Fri,  3 Dec 2021 10:41:46 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214861] UBSAN_OBJECT_SIZE=y results in a non-booting kernel (32
 bit, i686)
Date: Fri, 03 Dec 2021 10:41:45 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: melver@kernel.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-214861-199747-QyZHKm0Uqh@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214861-199747@https.bugzilla.kernel.org/>
References: <bug-214861-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UGyt6c7B;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=214861

--- Comment #4 from Marco Elver (melver@kernel.org) ---
As a reminder, in its current implementation, fsanitize=object-size relies on
__builtin_object_size of the converted-from object to determine if the
converted-to object could -- due to its size -- __potentially__ access
out-of-bounds bytes.

Also UBSAN_OBJECT_SIZE is already unavailable in kernel builds with GCC, so the
below is Clang-specific.

Example program that illustrates what [1] is doing:

---
// clang -O2 -fsanitize=object-size ubsan.c
struct sk_buff_head {
  volatile struct sk_buff_head *prev;
  volatile struct sk_buff_head *next;
};
struct sk_buff {
  struct sk_buff_head list;
  int foo;
  long bar;
  short baz;
};
void ubsan_fail(struct sk_buff *skb)
{
  skb->list.next++;
#if 0 // uncommenting this no longer causes failure! strange, isn't it?!
  skb->list.prev++;
#endif
}
int skbuf_xmit(struct sk_buff *skb)
{
  struct sk_buff_head list = {};
  _Static_assert(__builtin_object_size(&list, 0) == sizeof(struct
sk_buff_head), "");
  _Static_assert(_Alignof(struct sk_buff_head) == _Alignof(struct sk_buff),
""); // not UB!
  ubsan_fail((struct sk_buff *)&list);
  return 42;
}
int main()
{
  struct sk_buff s = {};
  return skbuf_xmit(&s);
}
---

I was really struggling to understand why a small change (see the #if 0) would
suddenly no longer trigger fsanitize=object-size. I guess this has something to
do with what optimizations are applied and the visibility of
__builtin_object_size.

Furthermore, as is evident from the first _Static_assert, it's clear the size
of 'list' is always known to the compiler, which fsanitize=object-size relies
on. Yet subtle code changes no longer trigger UBSan.

And in the above there is no UB as far as I can interpret the C standard --
"6.3.2.3 Pointers": "A pointer to an object type may be converted to a pointer
to a different object type. If the resulting pointer is not correctly aligned
for the referenced type, the behavior is undefined."

So what does fsanitize=object-size actually try to catch? Per documentation [2]
"an attempt to potentially use bytes [...]" -- yet, its report is generated on
the cast itself, not on the access.

It doesn't actually catch UB pointer casts, and it seems its only purpose is to
report on _potential for_ out-of-bounds accesses, although it's only guessing.
To catch UB pointer casts due to alignment issues we have -Wcast-align. And to
catch real out-of-bounds we have ASan (in kernel, KASAN).

I think the major clue here is this line:
https://github.com/llvm/llvm-project/blob/c41b318423c4dbf0a65f81e5e9a816c1710ba4f6/clang/lib/CodeGen/CGExpr.cpp#L733
, which has existed since its inception:
https://github.com/llvm/llvm-project/commit/69d0d2626a4f5

If the plan was always to rely on ASan or some other dynamic check to check for
OOB, this has never happened, and fsanitize=object-size is therefore
incomplete.

Like a compiler-warning, fsanitize=object-size appears to report on poor design
or interface choices, but is oblivious if a real out-of-bounds access occurred.
This sort of checking should not happen at runtime.

So my conclusion from this is:

        1. fsanitize=object-size is unreliable, and cannot
           deterministically be triggered.

        2. It does not actually report real UB if the objects have
           compatible alignment and no out-of-bounds bytes are accessed.

        3. fsanitize=object-size should be a compiler warning.

I think there are already several compiler warnings that can catch real OOB
where the compiler knows the object size (-Warray-bounds), and for the rest
there is ASan (in kernel, KASAN).

I would therefore propose to remove UBSAN_OBJECT_SIZE, given the above and the
fact it's already unusable in the Linux kernel.

[1] https://lkml.kernel.org/r/20211111003519.1050494-1-tadeusz.struk@linaro.org
[2] https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214861-199747-QyZHKm0Uqh%40https.bugzilla.kernel.org/.
