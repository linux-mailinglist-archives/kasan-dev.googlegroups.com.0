Return-Path: <kasan-dev+bncBCCJX7VWUANBB4FK26BAMGQERUKY2NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 20B74342B9F
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Mar 2021 11:58:58 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id f10sf24810318plt.6
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Mar 2021 03:58:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616237937; cv=pass;
        d=google.com; s=arc-20160816;
        b=BfeaPuBttzdAcfZG9VyFVFNv3QMg1Ji1tUmupC5nhzwxx9dnq4Fu0qpH5yUS4xDE4z
         uzj1qXnzSzjwQz9sE4eBCqblRy4si3ikH7RuRa/+dEUAjHX2xDveO82zEhpJUz1yLaj1
         LQZ7lT/gp815MsbK507m60OI8by8vmW8faQUGVZgSHfNQdBFpTFHYrFnL6JkrJ3K3Amf
         3ITJPcYRRpnW22c9pvq1NcdUVVUKYal7i0XsSQjp9X4f483H+whJXHqBp43ehLsLTcoN
         ZW5eY1NynCowjNks50VCUtM4KArbPJ1+5qJIXR9nIZyM4cm1C1Upc/7D+pmPJEmz9OuM
         Aymw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=BZ+DZTImwphDmnTrMxupfa/S+6bGtCrwzXf1NonfJbo=;
        b=xMcGF77iHvV1WQb1TDLJGGNM7gIndpu5QBjSt3k3c3BGPvxeZK4+IZahA1QIAft/T4
         kNXom9NELUcXqZHiS7TfXOavCrRgkgGm+eWdl5Jn63W81/nRoZAmPfOwvFXialZoLF+p
         Nj3EXdegVfvbfK9wu3GWqI8JLrCve4QEk34XrecFTp1mWabyLH++DJH7cfwc+VQoz3rH
         6TLBPSU0kjFmbNZFnn1sRn5r1d4ij68z+VzZgt6oN3YjOpTV5Pi17riydf0faMfIGECr
         tMNZSPsC2Sr3wOY5UnqfAgdfqAmAJpfMAi014dMZyUr4xKaQ7gwZsLX8P9hQbb4Df5pO
         LiXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=MFdk55cD;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BZ+DZTImwphDmnTrMxupfa/S+6bGtCrwzXf1NonfJbo=;
        b=ca8VkGkoqUIZI9U9V34P6RWBL60Jj8Wm5p4shvmxXV+ad0OC0H7DeXfzV8tTdr394t
         izAlVDuryoFmj6i0lhf8pr6eP13O5C+MZSjrFT/aWRrlj9a/vyYq4dCHJZFHJBUj6x5U
         wRXKKvK5LTElx9/XTUKpwzk7o7DHSiumk68bw5W+GhCqLvtMErctq+Wq/pRTfijB2kcV
         4RJLxx/qyLJT2Dx23CsUPfr+lrFuKlR2edc8IDSKeWRO+6psvbmVaKCuyfjwDaT4PcZk
         Ki0Arbsy80R1Mz6DVMM5IL7+ul8XN9ZuY0n/yhnxyC8PQ/yAlUy1qiqgvO5ANfBosLav
         +X7Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BZ+DZTImwphDmnTrMxupfa/S+6bGtCrwzXf1NonfJbo=;
        b=cV7LVLTz5lFamsWs+/dfdaObUFAJgGOMKT5/vStnW6PbIl3Ql0QF9yPsbGqwpLc0TO
         1NL9g4/0FD/oUQNCx0LooMWWCwobQ7eymbj7xRuKQELb7G2e9f8hX8cyQ7w0ibv8KH38
         t9zJQEJjcPszgSOEFxnBf397CqakEvtqav58gBuLMH6OmUIhaQ1qu2+KMe5Ff9RFCA7h
         y58DhbAmReWOzHVGGzMbZQ+1KsCQ7nVown5FN8jihpwLfmjEZe7WtFydDi/YXAibLa6g
         RvpFtCtOpAf7DVmNscW4eGrxpHpdEBEiXwLm6/XLVAUXrMyZnHHzaI6HKzyHD0ZT5X0p
         2wHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BZ+DZTImwphDmnTrMxupfa/S+6bGtCrwzXf1NonfJbo=;
        b=H6RvC7Hy7vSfv0P8BzwnrhCaj3hg5CImFx3V9v4EL0X1Ttj510J1BWCo0n1EDvltFp
         BQ1DWK3nCb8up60b7U5dbnnMDwDyy0oo+2+FwkuEOxMrdby34ITFfCL8b0EdgBl1RKnF
         Kpzf6GZEhdI7usYM6u/Z2gBw9KoxAWATGtmRUFddInKQ95LZxJU4SKPzm3uCVUDwTRnN
         ZqhvD92OiYKvOEJ+DWYt7Vf3GEWXfWr/QhSaDGXtNViYOGoERO++yUFnPGBHw3GKWdF2
         gc8WWvPAInKDpbbpXzqcXPJyU50i3x8sUHwKMfCDOMFNYOu1geu9ReiK+jzPFMm1H3BR
         Mi0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532N/IssETnXYBLCfZQcH1fw4/TYljpg76/5iz7XGelUPmZw9qzr
	a7uNFD5aPWR+Lzyy/xYIKQs=
X-Google-Smtp-Source: ABdhPJwATlSB5kl8epR7fmRlKLmAVVamH4+1oaANCa9gKC/reGyAapdSQYgN1rSWDHHTHkptk2LYzg==
X-Received: by 2002:a17:903:22c1:b029:e6:8800:37c7 with SMTP id y1-20020a17090322c1b02900e6880037c7mr17857638plg.61.1616237936863;
        Sat, 20 Mar 2021 03:58:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1393:: with SMTP id t19ls3445451pfg.3.gmail; Sat,
 20 Mar 2021 03:58:56 -0700 (PDT)
X-Received: by 2002:aa7:960c:0:b029:1fa:8cbb:4df4 with SMTP id q12-20020aa7960c0000b02901fa8cbb4df4mr13219889pfg.12.1616237936340;
        Sat, 20 Mar 2021 03:58:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616237936; cv=none;
        d=google.com; s=arc-20160816;
        b=JwXOOYn1qgKF9te5wlHEdCC/6j3ks7Ht/4is3DkzRgUidXjLS/3XaGx+ovyzQ9i3lB
         AsfDOonOy6v0b11HcvGjtS/ZVVYLmCMHdFJat/CNhm21K+iz9e7ws4S9C3/YxA3trDVd
         o2Ztm9/d0/s6uewXWbeK3a9ZS6SGMmi1R+3maJWz6ej81GzA+kVWOermejUqMu3Gmglc
         5HiB722qXBU05e5ILMIkedZ79tBN2JlWtiEisO6SAa3daxg7PWXoOmvP3hhBGL1gvNtN
         +ramNRzC1oafLHQBH5/1OzeYhPiSX9pk1ONe/y5KCIZL0bJobXydHYkd8KdblLPfqeRT
         E7ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U5zI2N5eJsydBU4Kcf42YOrHjn6io9gty356v6rFjA8=;
        b=dSYAzqmD9OYedKuQOI2i5FmcoZfW5fR15Xi8BsGpfl4kyFl6owJvkm/bydn4Vw8Nja
         krJ9jZ+8v11Zsrq5TBpmrfWx0q8luUZNS049te9Evt72miu9aHq96ODH57Wr6C7zNo2v
         PjB9IrUAVsxzC9m7IvJyUrBTRO+hy38rafHd6mLolTQQ7vIJ1T5mla82Dvz1hnKRLchH
         4yFz3qdPlD+05r6e3EK8ir5+6gm5bJPJsw5FsD8VER+58DIUMklIYFbA0pg9icStnf7e
         vVe0yRAQdVPl3bmxFAb9U17o+1hLqFkDYq5U69D3dUVCuAWdNa5+cqaG3a4BO1n9VWJF
         t2ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=MFdk55cD;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id r2si527423pjd.1.2021.03.20.03.58.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 20 Mar 2021 03:58:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id ha17so5922844pjb.2
        for <kasan-dev@googlegroups.com>; Sat, 20 Mar 2021 03:58:56 -0700 (PDT)
X-Received: by 2002:a17:902:f242:b029:e4:6dfc:8c1f with SMTP id
 j2-20020a170902f242b02900e46dfc8c1fmr17927976plc.0.1616237936028; Sat, 20 Mar
 2021 03:58:56 -0700 (PDT)
MIME-Version: 1.0
References: <20210206083552.24394-1-lecopzer.chen@mediatek.com> <20210319174108.GD6832@arm.com>
In-Reply-To: <20210319174108.GD6832@arm.com>
From: Lecopzer Chen <lecopzer@gmail.com>
Date: Sat, 20 Mar 2021 18:58:45 +0800
Message-ID: <CANr2M19+FtoAiEgKecJFdkdhaBLidiGjFvNY1f1kOMsvdQZEVA@mail.gmail.com>
Subject: Re: [PATCH v3 0/5] arm64: kasan: support CONFIG_KASAN_VMALLOC
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Lecopzer Chen <lecopzer.chen@mediatek.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, 
	linux-arm-kernel <linux-arm-kernel@lists.infradead.org>, Will Deacon <will@kernel.org>, 
	dan.j.williams@intel.com, aryabinin@virtuozzo.com, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mediatek@lists.infradead.org, 
	yj.chiang@mediatek.com, ardb@kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, broonie@kernel.org, linux@roeck-us.net, 
	rppt@kernel.org, tyhicks@linux.microsoft.com, robin.murphy@arm.com, 
	vincenzo.frascino@arm.com, gustavoars@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=MFdk55cD;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::1034
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
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

On Sat, Mar 20, 2021 at 1:41 AM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> Hi Lecopzer,
>
> On Sat, Feb 06, 2021 at 04:35:47PM +0800, Lecopzer Chen wrote:
> > Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > ("kasan: support backing vmalloc space with real shadow memory")
> >
> > Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> > but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> > by not to populate the vmalloc area except for kimg address.
>
> Do you plan an update to a newer kernel like 5.12-rc3?
>

Yes, of course. I dealt with some personal matters so didn't update
these series last month.

> > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > Acked-by: Andrey Konovalov <andreyknvl@google.com>
> > Tested-by: Andrey Konovalov <andreyknvl@google.com>
> > Tested-by: Ard Biesheuvel <ardb@kernel.org>
>
> You could move these to individual patches rather than the cover letter,
> assuming that they still stand after the changes you've made. Also note
> that Andrey K no longer has the @google.com email address if you cc him
> on future patches (replace it with @gmail.com).
>

Ok thanks for the suggestion.
I will move them to each patch and correct the email address.


Thanks,
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANr2M19%2BFtoAiEgKecJFdkdhaBLidiGjFvNY1f1kOMsvdQZEVA%40mail.gmail.com.
