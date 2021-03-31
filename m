Return-Path: <kasan-dev+bncBC24VNFHTMIBBOPASOBQMGQEYOWDTGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 158433509D1
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 23:57:14 +0200 (CEST)
Received: by mail-vk1-xa38.google.com with SMTP id x23sf1169276vkd.0
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 14:57:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617227833; cv=pass;
        d=google.com; s=arc-20160816;
        b=hlvQ/MW3jFBru4jh/YjcmcCl9os1dtUHE40706TBaWLeO6u6JtAx1sDr01jUEteo/f
         drIJLMmv9X/qKHFo2yIeuChRblLnb1jEo0QCzkBWsC2qDmM5Ei37FB1QS2kXOjiOvACb
         nXjq8jdjX6Fy7Wr03LM+zB82BYQVTMpwO7k1nSjmJryUIbK04lxUQ0G43BzXjB8P94s1
         vwfbqpF/lqe40lA/uWPUhfz04XLT9d1/cgz8TOECzzBaP0zsqgU/Mpxhhc9/dckxeKGp
         Gv2zvxhu7Caw8UqKWnGqyww6RPjF9reosc7r56gB3X1kvtccg+6KiaW2T0tLd4YknUjn
         01Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=vJn0Fz2TDedV2Z+tDVPAn7CcSlLdgRABfG8GhVWhlTI=;
        b=pQvh8GXYFxTuBtd+0MSHcu2Yn2GNLaOjmKjpK/McbO8trIfhboP4kuVD3DQucAHAR8
         s2dSZitgciNbeWjl4gDPPS1T/VWySkmvQH8D27wMME/1Us+MN0/VtOE6te7hKd3MAio6
         QhKNcu5Bf05iFGm7jdykO+j4zTsnLnl9/XNCzA/gWyGq7tmAbdkgQIe5ulKY6O5mPLMu
         +YE4UY9Vv2m9bDrM8stiPsc0eTFCPY112JXedKCWFvuZ5ebCy9NxJhF2H4xVc+HmJlnp
         7rrfTqaILunkPwE6dXI9m3t6IPqleTgw2kBe/Mnbab5Uev8zpzxv7CU7j0S3WS/aSdMk
         1F6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mxrLKb96;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vJn0Fz2TDedV2Z+tDVPAn7CcSlLdgRABfG8GhVWhlTI=;
        b=AReWiV4Bu5dIy/Kda7V9lS0m1rVKHIbxmtiMDLTnJyfr2qHU55eSAL2eDisiZpXyVD
         OJpHc0jC1xbzav5eFsV8RRdEegILXfLsEoq8MSmR42tl7qYx2sxHmBZKKoJrcQOeFSdd
         jkY4Ce3kx9DHYoNmyxf3f3BPEQvRizkUY8blJT+c0DL2iVTSp1L2lHHFLhpAXlq3lDHc
         0oGyLC9Tiahgj4ythueBgm612o1dk7w4/U1CTqSAc8dYdZVUSg5QpBWo+Ndhe5p+fEd/
         cgJT7InqO04DdfzZ3p0LaFRn9vTKzlTLVQAtFIoPE4111SU192W0duNGpdew0qxNJzpc
         hxFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vJn0Fz2TDedV2Z+tDVPAn7CcSlLdgRABfG8GhVWhlTI=;
        b=eBh0n2TsX1IP10f6p4BHsTe5q/Ek5SdSWxWPcPPSDFbgs8GJYXQUCPKjwmjO02wY0C
         Ve6l66cmzQglJrCkZAJAttv8MqonKDVE+3FTuzSj4evJlqIBHPiunRM+embjv5KS16Ar
         pYY4pMC97XMxSzmEZ2Z8RQvt159fM5YL6OzLcOZwge9RNcMvdt8bYu3QsENH2muib7wC
         ughACGt29S3kItgas4NHD6hhWAkUsQeUj1yQKls2a54/Q0VHXh+ik/VLAgaNJHp4qadF
         Dj2E0qlPssfDXavr1T1Axa0OZ+0Ec2K+GmeNwaYLel8oj3EfA/yVPodvXEvbRil8w33W
         NutQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SbtFhRy+qU2S+jOTprGt6RJrhDTxAzm9YB1T+jC7mNRC5A3n4
	y0ljn8qL50rIoNUQak853jU=
X-Google-Smtp-Source: ABdhPJyc45qhUPwnjSWrDmeODd26SzNRZSLkGjEA2S/uK44mbPP+ClFadPKaykN+HF3yDiRLaM7gwA==
X-Received: by 2002:a05:6102:b13:: with SMTP id b19mr3193613vst.42.1617227833184;
        Wed, 31 Mar 2021 14:57:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6f05:: with SMTP id r5ls268472uah.9.gmail; Wed, 31 Mar
 2021 14:57:12 -0700 (PDT)
X-Received: by 2002:ab0:14f2:: with SMTP id f47mr3132972uae.12.1617227832727;
        Wed, 31 Mar 2021 14:57:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617227832; cv=none;
        d=google.com; s=arc-20160816;
        b=l9IMyQu3cfkf+cPM1N93bX2ewNyN1N6G++VcJdqiBfX7ru9FnNvOZHEPRrXWXmhuyU
         jZgHV4DKl4CusX7RCk915bVtKqKvoA0XFlwnf15xX3dl9NlCnY14GN5RH8Ko3MvpWDZ1
         Zjh7SjbIOw2rCLm1ivUtGEpw80aMBdnWyHxh1cD5V/2kZG83xoPSXlclp8SQamFKD/Uv
         XQV3tenPsTcZIWsMAUz14/Bq8N6UsPmyPz/v6S67ZLs8WNzjprHhlBrDgnZ8KWzVq8AN
         0yBfQN67YxRI96kfThRmyNsU87QFiGf30AGXBcWCdNsAKTGpr60g6qDdKEugXyuvHkvH
         soqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=ed9VpXrsG2GhHT+/Lwnl2v7h74LRxyHm62WNT3K5QAQ=;
        b=QWWykpewIIIOThkxT8aYsNdXU2HydgYDLD+IRoE742vsGfutTpwT2+XMmL1M8mUxVm
         b4262ROmXXASAmZA9WWDxpfR+jyn+gd/QiFJ2XrOcLa+PkPoF0sagQXj8eImjcrIbsRt
         dHDggi0uxbkM0LKoglP3aH1ygXEv9uEIhLLUy1WYAuRxoB4ByfXHiWT86mbRnCSyoe4Y
         LfVgqBoPEzq5GGHNEMvvEIUolsimczEG8cZaD7Ohi+WC/59KCtKTmiNw6lKxALzp0Zi9
         dNljl//q5y5n3FGUy0S1Nd+sICoSUd/RQV4JoEZdo5CZ2Xb7wI/zWLowl+hfAq2ExaAO
         m08Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mxrLKb96;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v23si242189uak.0.2021.03.31.14.57.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 31 Mar 2021 14:57:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 859B261059
	for <kasan-dev@googlegroups.com>; Wed, 31 Mar 2021 21:57:11 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 759F360EE5; Wed, 31 Mar 2021 21:57:11 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212513] KASAN (hw-tags): annotate no_sanitize_address functions
Date: Wed, 31 Mar 2021 21:57:11 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-212513-199747-AK3JxVIbUN@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212513-199747@https.bugzilla.kernel.org/>
References: <bug-212513-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mxrLKb96;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212513

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Here's a draft of test case that checks functions from
include/asm-generic/rwonce.h:

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index bf9225002a7e..b9d942ae5c7a 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -1062,6 +1062,37 @@ static void match_all_mem_tag(struct kunit *test)
        kfree(ptr);
 }

+/* Check that different variants of READ/WRITE_ONCE() work properly. */
+/* XXX: some of these fail in QEMU due to:
+ * https://bugs.launchpad.net/qemu/+bug/1921948 */
+static void access_once(struct kunit *test)
+{
+       char *data;
+       unsigned long *aligned_ptr, *unaligned_ptr;
+       size_t size = 128 - KASAN_GRANULE_SIZE;
+
+       data = kmalloc(size, GFP_KERNEL);
+       aligned_ptr = (unsigned long *)(data + size);
+       unaligned_ptr = (unsigned long *)(data + size - 4);
+
+       KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*aligned_ptr, 0));
+       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*aligned_ptr));
+
+       KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*unaligned_ptr, 0));
+       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*unaligned_ptr));
+
+       /* XXX: these fail due to missing kasan_reset_tag(). */
+       READ_ONCE_NOCHECK(*aligned_ptr);
+       READ_ONCE_NOCHECK(*unaligned_ptr);
+
+       KUNIT_EXPECT_KASAN_FAIL(test,
+               kasan_int_result = read_word_at_a_time(aligned_ptr));
+       /* XXX: this fails due to missing kasan_reset_tag(). */
+       kasan_int_result = read_word_at_a_time(unaligned_ptr);
+
+       kfree(data);
+}
+
 static struct kunit_case kasan_kunit_test_cases[] = {
        KUNIT_CASE(kmalloc_oob_right),
        KUNIT_CASE(kmalloc_oob_left),
@@ -1111,6 +1142,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
        KUNIT_CASE(match_all_not_assigned),
        KUNIT_CASE(match_all_ptr_tag),
        KUNIT_CASE(match_all_mem_tag),
+       KUNIT_CASE(access_once),
        {}
 };

Note, that there are more functions that need to be annotated. Grep for
__no_sanitize_address, __no_kasan_or_inline, __no_sanitize_or_inline.

Note, that the test relies on the patch below, which is not yet in the
mainline:

https://lore.kernel.org/linux-mm/CANpmjNMpT0rYKfywkGvqLy8tk3iP6wAuGxHpHVJA77+EG4c5Gg@mail.gmail.com/T/#t

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212513-199747-AK3JxVIbUN%40https.bugzilla.kernel.org/.
