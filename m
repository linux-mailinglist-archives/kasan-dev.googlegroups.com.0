Return-Path: <kasan-dev+bncBD22BAF5REGBB4MM3GNQMGQEOQC5JHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CA2C62DE40
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 15:34:26 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id dt13-20020a0565122a8d00b004ac84274411sf753479lfb.8
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 06:34:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668695665; cv=pass;
        d=google.com; s=arc-20160816;
        b=r9QgQlj1rsvGArU/QZM9NiJlFrBezW/qFHPKiVdIVr1g5kdufY72yKXE5SvyQ4SkIt
         +kAn3ERe8R8JI2/Cuycv/eogEPr5KptjXLoH5/jugDMyQddScYAE6vOTocQOKMat91U5
         jzJbB8Xzv1cpAHZAlkXGkWaKn2pFhYMm/3x1/9GJEbPFWXxf7AjOMfNWt0tARZXCIwAR
         Sgj5HQjMsFd6a7P/6zb0odBCvY48bdaUPblbQys5Aj4/l8xQggOvxt1aMhWS3otnOYXE
         jK7qd4bEPjlC53iQ+bE8+MDgs7gvwu8rehpW4jDL57A6Y+U83NbmqTyQH6EScpKWwsxD
         QDxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=4JUYnj99GEqvshL6LEIntvMXVmfaGzDF+r7gWivVxq8=;
        b=uomVxI2e/fMZxA/oWYA229Vqf9rD6SHr7vo34nJyCGo1GFzszZ1efABe8KkJxo9YC1
         iaQ5AZJ7D0n1gwx9PgabrK5kRtT9QpmiodMlsr48I42pzIiX+bHmZl/OECF3hOdLI9a0
         d/AqdoIHoM92/xuha4r8w5TncVbl5UMZN0Aoo9fIMInTQHaVNOsjD5mMsOwhLilNR10X
         /81031ub4s2lQ6IcxRDOnCQid80JRXgdLOctkWfyrQsMAoeQww+5w2OYVKkv8hxE9VPw
         7VvdwOQ/8TGDhSEqIGmfHsVyDPlQP/X0AShfUrJ9Tqiq24crNcQ0Uhzqf0FTxyHR6PAr
         c2Vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=LGwoec3k;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4JUYnj99GEqvshL6LEIntvMXVmfaGzDF+r7gWivVxq8=;
        b=CR2QOlwEbb9aVaXkvxB4CMgZrDJRKbuc97frCeesNIpNztUhSFVhL7dnTylSN1XaIz
         3RL+zg1Vl2hSbiFymFGjLzWlPDob7mU3kvVaQo8E93zrDmr/j/tvLHKuRDv7u1t5Flgy
         PwfFfoHonUgdx0W73y4UliOktYd72+KDBaA+8mRaIyShQm6lFDPsFzRvKCCwNTC/9irS
         lEkafm35wcRzKasGFO6PbZrq7+49Cu2Rb/m03nr+mMsIfTD7EJturskWU77mo4vndkBs
         E7Z+7oRDxvN7IE2qnWAGTdpqIWYXRz1H1nMAzzCc6CFp4PO/ifE7C5GwfhyXp8zA6hmM
         8n5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4JUYnj99GEqvshL6LEIntvMXVmfaGzDF+r7gWivVxq8=;
        b=rsnp/cxnu1YgHQDsYXoO25LAGT2N2OZTtI0/XqfnY4bauUNY6SIRmX1LZQIMmXRF6f
         x71XzrI6dwPbbOx9/x7Hgksc7CNoPi9M9+ILQw7Cc2F79OOv1UvCQIGnzOol1FX8TaB2
         8dBlMY/cOWsYyQWyu/JNrrE2WRfL6Pz5DXe3IzgpowE5gAoHXKUlLtDKdgDDaFqFkIfZ
         2quq48HEomdShJe88aR73IdfwBQnd/vve9efD+o2ZkwIxJ7+6HDeLUPjH+wItA9Xc1h4
         EYUtGK/iK4O9vU/M4F0JJLKwqvOF2qU5Ss2boNBMhZJY0PvGnrepIQGS011J0LTwElvj
         k/rw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5ply75gnF4Buw5M63Uy9T/x+l6Sn0aM7Irlbq9Ap2gJ9YnCByJ7j
	6DK3cn2TLuUzl3cIOZEX5i0=
X-Google-Smtp-Source: AA0mqf5wAnsi81ZldH56ZTMb93zCXjvi3xQzOj/OKLdNl1aph2+3hU8yOCJ6rJph9A1lLIRorvl29Q==
X-Received: by 2002:a05:6512:3d0a:b0:4af:b981:35c6 with SMTP id d10-20020a0565123d0a00b004afb98135c6mr1160496lfv.232.1668695665619;
        Thu, 17 Nov 2022 06:34:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3603:b0:494:6c7d:cf65 with SMTP id
 f3-20020a056512360300b004946c7dcf65ls1627354lfs.2.-pod-prod-gmail; Thu, 17
 Nov 2022 06:34:24 -0800 (PST)
X-Received: by 2002:a19:f809:0:b0:4b4:b5ad:a645 with SMTP id a9-20020a19f809000000b004b4b5ada645mr986375lff.672.1668695664389;
        Thu, 17 Nov 2022 06:34:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668695664; cv=none;
        d=google.com; s=arc-20160816;
        b=XNXLYFNxIOPJIXumPI/Deg3adGvRyybhwHU00jkwi4ajETm8kQcGpyO/kgWuBW08lz
         z2nfYKXb54eIdcQ/L2Nqm015BRcpbDFDqsYqFlTl+CsLmba5FyKFaKYB3xGkhD1TqrU4
         1/jfSvs7ljfQSCQSK8NKJwSE/UQEo4Z/z/KIK/hp+gSigYDU52FFJxPLZaZUhC8lSRAu
         Y0Due9v9M29/MayKGx0OQ4DYVUXXWwn5i41vtvyXH9xcg0mkSQRzLx3M+LyIFjinX9wm
         5u+Z9DRj7/o9N1NTOsJ+NqIfyMnFlGgIdwLuG6iO3/05tyIIvqDu/DuxySabCoThbkWG
         vIxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=Rheq+ZxMbHkBrxKU93ry9KVh/cRbDRoveXkhfctTehQ=;
        b=FrbLHMcQl+z2zqYcjF6mULbDbTOQD52sgn8gapNXEMWLzUVAligHTPGLAwyIC1Qwxo
         Oq+iaQLYJrQrw9mOafAXmoSCrHIpXenQEwbwj0UR0nOa6AfhE9uIvVYivt27U2vMn3pJ
         6LQQDs04FBIneeUnhS6vsjPYzAQylKwjB1urqwDKRYCaunz+EAUjqKmR3f8QOXUuWiuW
         YFGiYR+YjjTGiaasXayVKlj1tME25nJtWRIPbk+bCSM+MgZuSXNxdL8935XWydKkPSfb
         zjr3WPs7AS4t6q0Hrd474Np6/0mOt+67NfD2ZUXv77nDRgvRpDMXNs2pi8TcbhpgBuCc
         Gdsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=LGwoec3k;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id x2-20020a0565123f8200b004b01b303713si31455lfa.8.2022.11.17.06.34.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Nov 2022 06:34:23 -0800 (PST)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6500,9779,10534"; a="377129752"
X-IronPort-AV: E=Sophos;i="5.96,171,1665471600"; 
   d="scan'208";a="377129752"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Nov 2022 06:34:16 -0800
X-IronPort-AV: E=McAfee;i="6500,9779,10534"; a="814534057"
X-IronPort-AV: E=Sophos;i="5.96,171,1665471600"; 
   d="scan'208";a="814534057"
Received: from vrgatne-mobl4.amr.corp.intel.com (HELO [10.209.115.197]) ([10.209.115.197])
  by orsmga005-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Nov 2022 06:34:15 -0800
Content-Type: multipart/mixed; boundary="------------5Ob6KInVGuG0YbX9A7MUQQSR"
Message-ID: <4208866d-338f-4781-7ff9-023f016c5b07@intel.com>
Date: Thu, 17 Nov 2022 06:34:15 -0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.2
Subject: Re: WARNING: CPU: 0 PID: 0 at arch/x86/include/asm/kfence.h:46
 kfence_protect
Content-Language: en-US
To: Marco Elver <elver@google.com>, Naresh Kamboju
 <naresh.kamboju@linaro.org>, Peter Zijlstra <peterz@infradead.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>, X86 ML <x86@kernel.org>,
 open list <linux-kernel@vger.kernel.org>, linux-mm <linux-mm@kvack.org>,
 regressions@lists.linux.dev, lkft-triage@lists.linaro.org,
 Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>
References: <CA+G9fYuFxZTxkeS35VTZMXwQvohu73W3xbZ5NtjebsVvH6hCuA@mail.gmail.com>
 <Y3Y+DQsWa79bNuKj@elver.google.com>
From: Dave Hansen <dave.hansen@intel.com>
In-Reply-To: <Y3Y+DQsWa79bNuKj@elver.google.com>
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=LGwoec3k;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 134.134.136.100 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

This is a multi-part message in MIME format.
--------------5Ob6KInVGuG0YbX9A7MUQQSR
Content-Type: text/plain; charset="UTF-8"

On 11/17/22 05:58, Marco Elver wrote:
> [    0.663761] WARNING: CPU: 0 PID: 0 at arch/x86/include/asm/kfence.h:46 kfence_protect+0x7b/0x120
> [    0.664033] WARNING: CPU: 0 PID: 0 at mm/kfence/core.c:234 kfence_protect+0x7d/0x120
> [    0.664465] kfence: kfence_init failed

Any chance you could add some debugging and figure out what actually
made kfence call over?  Was it the pte or the level?

        if (WARN_ON(!pte || level != PG_LEVEL_4K))
                return false;

I can see how the thing you bisected to might lead to a page table not
being split, which could mess with the 'level' check.

Also, is there a reason this code is mucking with the page tables
directly?  It seems, uh, rather wonky.  This, for instance:

>         if (protect)
>                 set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
>         else
>                 set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
> 
>         /*
>          * Flush this CPU's TLB, assuming whoever did the allocation/free is
>          * likely to continue running on this CPU.
>          */
>         preempt_disable();
>         flush_tlb_one_kernel(addr);
>         preempt_enable();

Seems rather broken.  I assume the preempt_disable() is there to get rid
of some warnings.  But, there is nothing I can see to *keep* the CPU
that did the free from being different from the one where the TLB flush
is performed until the preempt_disable().  That makes the
flush_tlb_one_kernel() mostly useless.

Is there a reason this code isn't using the existing page table
manipulation functions and tries to code its own?  What prevents it from
using something like the attached patch?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4208866d-338f-4781-7ff9-023f016c5b07%40intel.com.

--------------5Ob6KInVGuG0YbX9A7MUQQSR
Content-Type: text/x-patch; charset=UTF-8; name="kfence.patch"
Content-Disposition: attachment; filename="kfence.patch"
Content-Transfer-Encoding: base64

ZGlmZiAtLWdpdCBhL2FyY2gveDg2L2luY2x1ZGUvYXNtL2tmZW5jZS5oIGIvYXJjaC94ODYv
aW5jbHVkZS9hc20va2ZlbmNlLmgKaW5kZXggZmY1YzcxMzRhMzdhLi41Y2RiM2ExZjM5OTUg
MTAwNjQ0Ci0tLSBhL2FyY2gveDg2L2luY2x1ZGUvYXNtL2tmZW5jZS5oCisrKyBiL2FyY2gv
eDg2L2luY2x1ZGUvYXNtL2tmZW5jZS5oCkBAIC0zNywzNCArMzcsMTMgQEAgc3RhdGljIGlu
bGluZSBib29sIGFyY2hfa2ZlbmNlX2luaXRfcG9vbCh2b2lkKQogCXJldHVybiB0cnVlOwog
fQogCi0vKiBQcm90ZWN0IHRoZSBnaXZlbiBwYWdlIGFuZCBmbHVzaCBUTEIuICovCiBzdGF0
aWMgaW5saW5lIGJvb2wga2ZlbmNlX3Byb3RlY3RfcGFnZSh1bnNpZ25lZCBsb25nIGFkZHIs
IGJvb2wgcHJvdGVjdCkKIHsKLQl1bnNpZ25lZCBpbnQgbGV2ZWw7Ci0JcHRlX3QgKnB0ZSA9
IGxvb2t1cF9hZGRyZXNzKGFkZHIsICZsZXZlbCk7Ci0KLQlpZiAoV0FSTl9PTighcHRlIHx8
IGxldmVsICE9IFBHX0xFVkVMXzRLKSkKLQkJcmV0dXJuIGZhbHNlOwotCi0JLyoKLQkgKiBX
ZSBuZWVkIHRvIGF2b2lkIElQSXMsIGFzIHdlIG1heSBnZXQgS0ZFTkNFIGFsbG9jYXRpb25z
IG9yIGZhdWx0cwotCSAqIHdpdGggaW50ZXJydXB0cyBkaXNhYmxlZC4gVGhlcmVmb3JlLCB0
aGUgYmVsb3cgaXMgYmVzdC1lZmZvcnQsIGFuZAotCSAqIGRvZXMgbm90IGZsdXNoIFRMQnMg
b24gYWxsIENQVXMuIFdlIGNhbiB0b2xlcmF0ZSBzb21lIGluYWNjdXJhY3k7Ci0JICogbGF6
eSBmYXVsdCBoYW5kbGluZyB0YWtlcyBjYXJlIG9mIGZhdWx0cyBhZnRlciB0aGUgcGFnZSBp
cyBQUkVTRU5ULgotCSAqLwotCiAJaWYgKHByb3RlY3QpCi0JCXNldF9wdGUocHRlLCBfX3B0
ZShwdGVfdmFsKCpwdGUpICYgfl9QQUdFX1BSRVNFTlQpKTsKKwkJc2V0X21lbW9yeV9ucChh
ZGRyLCBhZGRyICsgUEFHRV9TSVpFKTsKIAllbHNlCi0JCXNldF9wdGUocHRlLCBfX3B0ZShw
dGVfdmFsKCpwdGUpIHwgX1BBR0VfUFJFU0VOVCkpOworCQlzZXRfbWVtb3J5X3AoYWRkciwg
YWRkciArIFBBR0VfU0laRSk7CiAKLQkvKgotCSAqIEZsdXNoIHRoaXMgQ1BVJ3MgVExCLCBh
c3N1bWluZyB3aG9ldmVyIGRpZCB0aGUgYWxsb2NhdGlvbi9mcmVlIGlzCi0JICogbGlrZWx5
IHRvIGNvbnRpbnVlIHJ1bm5pbmcgb24gdGhpcyBDUFUuCi0JICovCi0JcHJlZW1wdF9kaXNh
YmxlKCk7Ci0JZmx1c2hfdGxiX29uZV9rZXJuZWwoYWRkcik7Ci0JcHJlZW1wdF9lbmFibGUo
KTsKIAlyZXR1cm4gdHJ1ZTsKIH0KIAo=

--------------5Ob6KInVGuG0YbX9A7MUQQSR--
