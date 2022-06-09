Return-Path: <kasan-dev+bncBDW2JDUY5AORBGX5RCKQMGQE7XGPHHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E0D7545447
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 20:40:28 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-f5ce935f21sf208727fac.21
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 11:40:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654800026; cv=pass;
        d=google.com; s=arc-20160816;
        b=qDJ+01gEEbpimRnHIaUYTQV4YrSSdcKD4sB/Uw8SNZ6FI/ggrW2CezyhNxbe9Qgwfy
         0OhW6COQIpfia9MYIbPlcRCPiTfj96Ik8q5aw+BPpGHShsgNZwdpVn3/SVuv4tU6luA/
         tabWgl1zftXNsELICaJ4dsuFsg2pA4P4PSnBVUblaUG+cDQUet25kA8e0H6dwOH8H6ru
         jyXKXT0xSwUj6joqbLUaweyEdco0PxuepmZ83P0AgqbHzIsKHYS+MAl3MHPbgznN8XKA
         kJoR05Un96x01XEtpKLa57rXriqnQ26UuIueqkbm39iFtlTO7j19jJHydaBYoEfmfiQL
         U9dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=TM6kLBKyOPvFE/25vy08tNW42pfODsypG9EyXl9z4pY=;
        b=wa51KI25+vg6p3WN0aPPBe49OEAlhLUZE/IC7PLznHBXJDgbnZ4lforX9fIs0ScD49
         baJBKe0+yLJRJMNXmAYhVECN1IZX+0HPBQTVN+SbK+ZUBZ3nH6ra45LvSTOLT9r3HPIN
         9PBANpoF+QzHrnhF2ep6zdy7bSBLjF9Il+M75M1V8Ja6OXFf5c9jXLXEk8JbNABrvpR3
         t0pc9yqQTTZDCBzZQFGaFSmbFQU93wkCTFeKVHPK/7VAnTx+zbjjqt3fS7CCn5dV7vUR
         A5QjXqS9vowRl/fxcm6GSdVUSYREwuSTSp/BnxdDE0eHI548LZoM2Qq7HTAWTr4u/EeG
         dm+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="I3v95p/E";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TM6kLBKyOPvFE/25vy08tNW42pfODsypG9EyXl9z4pY=;
        b=mGg7xp2635tQ/ag6zcnf8YiEfJVh+PYRZFa041W9AVrKNvsg/GNYCgJnodeAbWiYvj
         iJ/Iqtd90BZsn+PsxJFdKSDIVGOJdiqR9dDQHTQBKdugkUP8Nzb4wGu3X9SRcswpX4gX
         k3rymQ6ioj8/4ZDd8gpu5M0Mqalzj/8KTc7KxQ4OgUO2scZlh/JCCloeK+g8HIMMsvll
         2JPVlMAh79pI8iKabF+NJgGzhnXWQvTq/76kdVVmBkizBRvDy6CNGTt2W5nS6qiJokaZ
         Gov1Wy7/ytxypYSVlb5tDAlZJ4oaf30gZ7uVV3M9HfUcNxAlS2t3DkwLG1eoZRTNjZ47
         L6eQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TM6kLBKyOPvFE/25vy08tNW42pfODsypG9EyXl9z4pY=;
        b=ZzzRQejU24B/7coWh8QgKpOOK8kw9Hh7agOioL/B3gI8fVdryxNPGTaEXZpxiIgSxJ
         fqykNMep5cznOf8cSbnNvYLF0vVEsGdn0pqeb4d9a1sf7QkcB/XcOOY3abIrGppptXQ7
         WepxTkgzJBCdowO88KOV+VWUdZIy+4w+oUShALUmytWOvQ0G0Gtxm54EURI5cEGaDcOK
         yRxZhvYp++qvlu+wjMF2aEts2jxe/m+exUCXRywPxV7gKS5cOl7l6IQXmka7v8yts3G6
         /LEU5j2mQ5i4s5fJkGQQBL9eJh6UL4X9MDC6ItNKq3Lh0s7vMQ8ZC0MlFewZ0u1GexUY
         KWhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TM6kLBKyOPvFE/25vy08tNW42pfODsypG9EyXl9z4pY=;
        b=lSzoAEcRgqAY5RQyXCvH/Lew6u2y1RNRZZeKd7ygt80VTsJe/kMmyCXg+waOBL0Pd9
         FFuhC590GzXLX0e6OteuUPPBRXd5jkM3ilr6bQ0X6lw26CkDBwK/icLqNfcAmx8Imej9
         nKIdnmFmbXuEiJ3FY8vrq3j4Fj4DOZkQphgZ2XjwW1gcnHfcldQVvi0QNcmPuoOuRyLc
         CBP+gqC0o38mYFmmm8JNJMXaRlg6EwbgmiWQYTMX+zYBUpgMOpeUsAOO1QNojb7U09Pr
         Ez1/dlqu1VMZschx8eH9LnsU461CQXFNH1dijH1PQZJe0dpJBrVyWzx1jxUfxWVCoaap
         WddQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tB4AfycXyObTALBJPa8LpdG2tT5WfF4kKASBzJvBL44CgKtYb
	flW4KjtUVFmP/ZiwY5T4Vzg=
X-Google-Smtp-Source: ABdhPJxmVIL4QBwQdK2vlD9A3IWlwT9x28vsUGlHV3Zna594d0QnL2Hlhew33o1THuQeA8e4hG0idA==
X-Received: by 2002:a05:6808:1495:b0:32b:bbf1:9fc0 with SMTP id e21-20020a056808149500b0032bbbf19fc0mr2424739oiw.65.1654800026818;
        Thu, 09 Jun 2022 11:40:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3c06:b0:fa:8e9d:2fea with SMTP id
 gk6-20020a0568703c0600b000fa8e9d2feals7700531oab.6.gmail; Thu, 09 Jun 2022
 11:40:26 -0700 (PDT)
X-Received: by 2002:a05:6870:51cb:b0:fb:5c97:bd1b with SMTP id b11-20020a05687051cb00b000fb5c97bd1bmr2550774oaj.104.1654800026164;
        Thu, 09 Jun 2022 11:40:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654800026; cv=none;
        d=google.com; s=arc-20160816;
        b=0b1KnZMTca/92JuyPlaTJCs0djrg9YWC9SKKjQxR/ev1dN5xywOdUOtUQA7HfZs6Ro
         PouHD1Fzo9JgCZJJk2BT7q9uLEaBWCbbDRLQ4KvKq7duzgaBBsE6tMfuFzhnBh+OmfS1
         Pov997OMU+89/aJ03rDZ+I4ZiEjH6hO0OgkQCfocQcS7yDWblQXAnHZwK9XehYvp6zcY
         FtgoV1oE+7SuGZrD7I4HCJ4FLU3O3XwqZnTLrz87EbB8n5JRLCXVNAuhgx1VT9ILBXBo
         YsLKIEORun2Ot0bi65ncls07rCtGA3l1x2MX96Xk/TB0lmBT0g8f7Bq/zJCwWuyuvhDC
         JZHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mhZnH0kJ/WCy7bKmgft3ZY4QPBGIAjoqTg3AZP5l4PQ=;
        b=1G3ylsSgJbMxwdEf4qltlBDBFTqEKbpP4NO8fejD927wSyBRY/UNsag5B3yb/7oiuD
         9hsXq0S+CTVoWLMixFTdCOqjqxRJtecGkHL/9VqFhpZMMitk7lT+T46t1YPhL34dIiZz
         nZAOvK0wcVdo3LxGdBMP9dubwEJt4HCvXGTlvpBdcHwF87J3LbPokTLpnYOAO23WZ+9l
         x4aqwRHz+MHYtP/tHQx9RQ0VYhlmsASMoPAJJx3BZQJgryyFelFBfUuWuEyT9OqE6IBl
         EINgF1nHaQy5iFtY1urOhlFy90aWks8p9M2nqAPuo0XH9DRi7FAyCiwUCrf8KPYGJbCn
         jhvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="I3v95p/E";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id i185-20020acaeac2000000b0032ec58735cesi359977oih.5.2022.06.09.11.40.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 11:40:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id s23so23038593iog.13
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 11:40:26 -0700 (PDT)
X-Received: by 2002:a05:6638:22cf:b0:331:a5b9:22f2 with SMTP id
 j15-20020a05663822cf00b00331a5b922f2mr12581798jat.218.1654800025920; Thu, 09
 Jun 2022 11:40:25 -0700 (PDT)
MIME-Version: 1.0
References: <20220517180945.756303-1-catalin.marinas@arm.com>
 <CA+fCnZf7bYRP7SBvXNvdhtTN8scXJuz9WJRRjB9CyHFqvRBE6Q@mail.gmail.com>
 <YoeROxju/rzTyyod@arm.com> <CA+fCnZe0t_P_crBLaNJHMqTM1ip1PeR9CNK40REg7vyOW+ViOA@mail.gmail.com>
 <Yo5PAJTI7CwxVZ/q@arm.com> <CA+fCnZc1CUatXbp=KVSD3s71k1GcoPdNCFF1rSxfyPaY4e0qaQ@mail.gmail.com>
 <Yo9xbkyfj0zkc1qa@arm.com> <CA+fCnZfZv3Q-2Xj1X6wEN13R6kJQbE_3EgzYMyZ8ZmWogf28Ww@mail.gmail.com>
 <YqI8zGRKa6GE+K1A@arm.com>
In-Reply-To: <YqI8zGRKa6GE+K1A@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 9 Jun 2022 20:40:12 +0200
Message-ID: <CA+fCnZdRBxdXCYgxDn2-JfqQhKjU_Auu9fQdvugZs_maHaQfSg@mail.gmail.com>
Subject: Re: [PATCH 0/3] kasan: Fix ordering between MTE tag colouring and page->flags
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="I3v95p/E";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi Catalin,

On Thu, Jun 9, 2022 at 8:32 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> > This would make __GFP_SKIP_KASAN_UNPOISON do two logically unrelated
> > things: skip setting memory tags and reset page tags. This seems
> > weird.
>
> Not entirely weird, it depends on how you look at it. After allocation,
> you expect the accesses to page_address() to work, irrespective of the
> GFP flags. __kasan_unpoison_pages() ensures that the page->flags match
> the written tag without a new GFP flag to set the page->flags. If you
> skip the unpoisoning something should reset the page->flags tag to
> ensure an accessible page_address(). I find it weirder that you need
> another GFP flag to pretty much say 'give me an accessible page'.

Hm, this makes sense.

> As above, my preference would be to avoid a new flag, just wire this up
> to __GFP_SKIP_KASAN_UNPOISON. But if you do want fine-grained control, I
> can add the above.

OK, let's do as you suggest.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdRBxdXCYgxDn2-JfqQhKjU_Auu9fQdvugZs_maHaQfSg%40mail.gmail.com.
