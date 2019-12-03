Return-Path: <kasan-dev+bncBCR5PSMFZYORBZV2THXQKGQEBCBVETI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id A528810FE54
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Dec 2019 14:04:39 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id x8sf2347134qtq.14
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Dec 2019 05:04:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575378278; cv=pass;
        d=google.com; s=arc-20160816;
        b=jk5A7oxSyp0bjiWuTyteomFXHcmZUFymYgAwc3PNATWIcxHhu6f1pkZU84FZTt+FYA
         pWeM7QHREIBL6lIlIcqlbo6s7Dn/Tl49y/m7cLigI5rOD6ktLR71PN+Ni6/se3vOCykP
         /npT98tWNYOQ3hpjAhNUPgORX60CxUxH/S9hO8+MZm2bhKISs+Ko4as0oODsqs0GHDaq
         KXc3Bck5tcurqI2jtjS41kFWhbYPtvJAr7U19h4dBbuPI/UeWoQZGOuJCj/tguT1hWfh
         KEjIvHNhyWXq5Ijhk1FMg2I0MD9FMr2Sl22MJ1FwxtlBkUM23AW4YCeDNbK64kODelWQ
         34QQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=UDHN4UFiGbr57rZIHloJ7GdaEmWFi8vv63vI2iJMwPw=;
        b=Q409DVWdDyO/o5B9UwcrDN8qSbiaJfkf/cpN54qvQUx+hbQoTYibu/pfccB15g0sFD
         5ELvJmV2tb8+ttqLqQv4bUorSECvcx0unucqQ6YelxkuAY9IE62yJde/7IY5FUx0yupp
         7AvB/qpjNrjrmgTKornrGGZNmPPXYWmPHGtlX/beEn/WvLXYDGMO8al4DOe5INnrMLji
         0Byn6PtUVCR8lqdqKGoI1j3FwHy8jR0J/UQPUXKKcQKHc1dP29ayfDQQSuAV/wnzFLQ5
         Z/0Kox88A4aV6pAswAjUDHrPyO12kOIE9+WeeU3O8yRRWvLejAlnWE2qN4ZnX2mym85A
         sa/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=VBhQwAU2;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UDHN4UFiGbr57rZIHloJ7GdaEmWFi8vv63vI2iJMwPw=;
        b=caLTjBs29TNRBoywbDwy0fwITKy6Jj5kKieKP5NfbKAzeKAgohjYF5Ugi4ecOWyfVI
         e6eRhrmAbXM+1f4h6j9HDKTB869qjzuMwt5dT9S8nWFZi2hnLzJrbk6ttI1JaiYwpong
         JW97HoxUSAFb2070+/5wZsypLAPx4XXKeCAYyZMddtNAPuvfeH39lkjLz4TzD0Iw0eix
         m1fn2CMWD0Qcy6dSD0J7JvsDvkeDg+e623vnTqZXeQaxJ9Koym8kqW6CxFHzB4SABiDH
         bBMQtjPu6x1hh4Sw2DqljfzbxvopCH5aW7B+MC9gnjGSWe/kZylyWRkTS94O5EY4nYK6
         ge1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UDHN4UFiGbr57rZIHloJ7GdaEmWFi8vv63vI2iJMwPw=;
        b=FUBobpYmjXIMN92nXT1KsKrIyu3/17PLOeyAztn/l5w5KLdRttfdELXE4BU8imds8P
         LjZvJ4ZdG+ijau5rPNg+8sagw3+dQOWGQ40VBswd7dwLrsIKC66/Ww+IUMc1PPCUEhYA
         2V6SdpYb/f8rdt3WXH1fIwHs9N23CC9N5QfPoXarZigVkGKEYngIqqcu+1W99SFHVwAl
         o9/O/3UKWinTnsTlz3iFpCQcCmahTS1sxCj13R6L/JvPoFpOjqqqCymnXGvAM52wUbHP
         XONsOzmGekfnZGqF0sL2/jVEAj6lLxYgSuTYHkw4q7ee5jWOe9Pqc/Sk3AQS4B9QaXTR
         TvNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUf5mt2tkXQleRrJHFBIOEwIMVvqX2O1K6N158pWnw9ekq59k6M
	jJn+L6qS4Y4csRa4Voc9/1Q=
X-Google-Smtp-Source: APXvYqzr0A3O6RxJIvIg2W5XpmtmUWEESdXLLnF4fbemNSpbM4gou6CTkPp3g9rTPS1FOmzNUAwaog==
X-Received: by 2002:aed:3e12:: with SMTP id l18mr4924228qtf.290.1575378278487;
        Tue, 03 Dec 2019 05:04:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3443:: with SMTP id w61ls842375qtd.11.gmail; Tue, 03 Dec
 2019 05:04:37 -0800 (PST)
X-Received: by 2002:ac8:460a:: with SMTP id p10mr4612809qtn.98.1575378277962;
        Tue, 03 Dec 2019 05:04:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575378277; cv=none;
        d=google.com; s=arc-20160816;
        b=Ope2Xjq0zkm48/UbZp25E0KqfniFLWgFPbPhlMrxIsTurDAfZREXlerPlZlX1RMd1d
         uVpLaHrV30q8jlXxKtFAIRVD/1XkymycE4USTjvDFX/m6rYKu0bm+azy7U3gOh8td+WT
         KOCsEG6m1i7Sp1tmVxqyZeai9ysUZCYv8nJKh+4R+vK/gowxUpV2pvYORcpjlltT91gp
         NTc5rd8OqZKAY76u6jOGXxOVlFjMWhQaYqV2kSaJceyxdRdBbu1qQlMpsgKvNjvM2IH0
         lChqRo7u3BiMoiuc8HkzBG31D4kl+gtsU38qIKYKdaW8rBaodnTCsmPThy1QsGDD4lcf
         mnrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=1JSgQXxEzwqR5TOeKeaYA4BbVMzL18p8VzHWemsWYT8=;
        b=wq9MPuvCh8XQjA5BwI2gD5C0mJVjnWP7nxWAnIFzbXwLiYcaFnKbOfg0Otvgd6WELD
         lDLPjyir+VwsugIelDrsJCh1TTZG0t1dTN28ZbpWJEdJIApPsMEgKGiyXJ7iuiN+J8k+
         eTYIm4yu4JUjOgqcve13xTpQ52qLigB+qFyYWK9OMJZhFjaJ1lG/Yn+heJELCjCaBALv
         UBHvxkPueSNQ50XLO2JE1EQ8FsEIiSyszKTu0rrE7btMowFpPWtlhYTLjFl4Zu4+dT41
         XEDQs73n7/NhI3M+NJiEoo4elOab7/UBTACx8nwQ30Oypjbec+DA0P8kWOltllJ+O3hu
         RPkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=VBhQwAU2;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from ozlabs.org (bilbo.ozlabs.org. [203.11.71.1])
        by gmr-mx.google.com with ESMTPS id k16si145703qkg.0.2019.12.03.05.04.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Dec 2019 05:04:37 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) client-ip=203.11.71.1;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 47S2Hy2kcFz9sP6;
	Wed,  4 Dec 2019 00:04:30 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Marco Elver <elver@google.com>, Daniel Axtens <dja@axtens.net>
Cc: linux-s390@vger.kernel.org, the arch/x86 maintainers <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org
Subject: Re: [PATCH v2 1/2] kasan: support instrumented bitops combined with generic bitops
In-Reply-To: <CANpmjNN-=F6GK_jHPUx8OdpboK7nMV=i=sKKfSsKwKEHnMTG0g@mail.gmail.com>
References: <20190820024941.12640-1-dja@axtens.net> <877e6vutiu.fsf@dja-thinkpad.axtens.net> <878sp57z44.fsf@dja-thinkpad.axtens.net> <CANpmjNOCxTxTpbB_LwUQS5jzfQ_2zbZVAc4nKf0FRXmrwO-7sA@mail.gmail.com> <87a78xgu8o.fsf@dja-thinkpad.axtens.net> <87y2wbf0xx.fsf@dja-thinkpad.axtens.net> <CANpmjNN-=F6GK_jHPUx8OdpboK7nMV=i=sKKfSsKwKEHnMTG0g@mail.gmail.com>
Date: Wed, 04 Dec 2019 00:04:23 +1100
Message-ID: <87r21lef1k.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=VBhQwAU2;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted
 sender) smtp.mailfrom=mpe@ellerman.id.au
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

Marco Elver <elver@google.com> writes:
> On Wed, 20 Nov 2019 at 08:42, Daniel Axtens <dja@axtens.net> wrote:
>>
>> > But the docs do seem to indicate that it's atomic (for whatever that
>> > means for a single read operation?), so you are right, it should live in
>> > instrumented-atomic.h.
>>
>> Actually, on further inspection, test_bit has lived in
>> bitops/non-atomic.h since it was added in 4117b02132d1 ("[PATCH] bitops:
>> generic __{,test_and_}{set,clear,change}_bit() and test_bit()")
>>
>> So to match that, the wrapper should live in instrumented-non-atomic.h
>> too.
>>
>> If test_bit should move, that would need to be a different patch. But I
>> don't really know if it makes too much sense to stress about a read
>> operation, as opposed to a read/modify/write...
>
> That's fair enough. I suppose this can stay where it is because it's
> not hurting anyone per-se, but the only bad thing about it is that
> kernel-api documentation will present test_bit() in non-atomic
> operations.

I only just noticed this thread as I was about to send a pull request
for these two commits.

I think I agree that test_bit() shouldn't move (yet), but I dislike that
the documentation ends up being confusing due to this patch.

So I'm inclined to append or squash in the patch below, which removes
the new headers from the documentation. The end result is the docs look
more or less the same, just the ordering of some of the functions
changes. But we don't end up with test_bit() under the "Non-atomic"
header, and then also documented in Documentation/atomic_bitops.txt.

Thoughts?

cheers


diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-api/kernel-api.rst
index 2caaeb55e8dd..4ac53a1363f6 100644
--- a/Documentation/core-api/kernel-api.rst
+++ b/Documentation/core-api/kernel-api.rst
@@ -57,21 +57,12 @@ The Linux kernel provides more basic utility functions.
 Bit Operations
 --------------
 
-Atomic Operations
-~~~~~~~~~~~~~~~~~
-
 .. kernel-doc:: include/asm-generic/bitops/instrumented-atomic.h
    :internal:
 
-Non-atomic Operations
-~~~~~~~~~~~~~~~~~~~~~
-
 .. kernel-doc:: include/asm-generic/bitops/instrumented-non-atomic.h
    :internal:
 
-Locking Operations
-~~~~~~~~~~~~~~~~~~
-
 .. kernel-doc:: include/asm-generic/bitops/instrumented-lock.h
    :internal:
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87r21lef1k.fsf%40mpe.ellerman.id.au.
