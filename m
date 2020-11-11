Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQPNV76QKGQEAX7FPDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D5CF2AF3B0
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 15:35:47 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id m8sf1280794plt.7
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 06:35:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605105345; cv=pass;
        d=google.com; s=arc-20160816;
        b=V7bJkMebyqz9XphiNBHk1J4DI3RQ2ii4XLls6hQa2DozDbDms0es05QFd9PG9SuakP
         ggGVGgnxk+ANxdTXThzt7PCNwjXTQ6ttpQx5xsKTF/lDnBUjuUqywenbTE9FUTF0iOyu
         C1/jvUD+LZJ07NMo1eS+TqodKUCWXdB6kwsnd75JXRffYFb9r/tZkRZN2I259kErwFR+
         6J0Ig6/s8CnHONUG4HCh3zQNNQ/u+9lb785s7DVqFXKzllGwMn9lZOP0O0InXtfjl4Sc
         OjdBrqSVjvR5yyjD14XUlz9D85PnwF+zszPBcQ9xI8KYqVJkvcielCTaB7XuImo3Sh4U
         5yFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zQKN4JaAFo3zkTdGqKhegVnC5i5RbU8kzVuFOqjBmSI=;
        b=ZiJALwtAJ6d2vYzUJ+wh9NpMPHIGNGCnD6jlzGBG1JDjWO6L0x377r4XyyFkduVSxa
         88pdVyWCioH1vdIzAOyjU+kuArXl9VkPzpe837IVZ4Z/IoLIpYF8nt4Gb2xd9MZxRcgP
         cn46V0DKWY8WjWymJUFw8mOzgpygK8TFMxvb9Y7wrJXE9/mulwXXhJtmN4nOkai+lZvn
         1k6Vg5RFoWU0xg68iaaDpIxHmTvegFreX0cainluAkE3Q+oLdPIFp85AwGR8CX8ZaTL+
         +rSjVqlTi93F+kK8s+kjWjgi0jCKOWopmm+n8T9LW9BHivj0FChablOBMbkKRXcSjq3o
         bdTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kzsM7g5m;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zQKN4JaAFo3zkTdGqKhegVnC5i5RbU8kzVuFOqjBmSI=;
        b=pBYLxtqqu8VS7cPbJu2ApT5C+UBkknlQv/VNQ9Uyr9M26Cyd3cllNHmzr8yqya2Kio
         rRwEt7dCsCc/wSzolXYOcBO1lfQ590uELEYGduXX3U+ext/N4n8vQgO4PSHNGBOhv1s7
         H5qSc1uSxk/eEy5m4GoGfwXskkxdDPHDE+7nA2s7eZin2NsXqN7rEiLZEiJK2pWVe6CK
         gTOap6ikCaIQXHiHVqKNsRcV16hzUiWsPi4IZgHXYB8fnzMdupcyxHQsg1BgVE5HfBU8
         N8UphtJwECLg/5+rInOE5UEs4Nu+f9sV4mi5Ol9a4Alw/+StpJt0KyxFkmNLwU4D90EF
         8dFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zQKN4JaAFo3zkTdGqKhegVnC5i5RbU8kzVuFOqjBmSI=;
        b=Q7CPYPb+ytDUlVfsfv06sf6hSvyCgjvSHmKMlsHH5duEL/uYu4HrjvxxDaXFs6AtbX
         iBmvYPYfh6cETobVEzBqaKEvfjxmzckaV2OtSRBXgLzRSOVbiff2z7nVk6PwYVwXlQyo
         3U9EcU48SC/QXv2KCLKZrr+j1T2UNo/1D3A01fSwH6krFht11tuQMYHxsnIO7XzdEI+w
         0nkyh+uppGMVQdjMIA//7FTMO1hogCjXMN00p9tKXu6ou59qYVucaslBS8S0hFBJ1cs4
         9r72LF6R+FhgVthDYkVle2oa3Hva2bBuZGfEaZ2OsYaTtAud/IVZUsLgMccFsOHSX/mD
         nAOw==
X-Gm-Message-State: AOAM531m5X/RqYW4HOlMVtDzChhm0jOq1a1K8cecAaH1+buJJq7Bq8SH
	2sGk5cdxMQGVZTIHxEb06BI=
X-Google-Smtp-Source: ABdhPJw9PDi7kkRQ2/nmJ2BtsRTAcuwwiqMOlT8I9OYyOK4A2My8Sn41wJmtAcGyeou/FGAp3/fOjw==
X-Received: by 2002:aa7:928f:0:b029:163:d44c:490e with SMTP id j15-20020aa7928f0000b0290163d44c490emr23286177pfa.60.1605105345469;
        Wed, 11 Nov 2020 06:35:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ea4d:: with SMTP id l13ls73772pgk.0.gmail; Wed, 11 Nov
 2020 06:35:45 -0800 (PST)
X-Received: by 2002:a62:e40c:0:b029:18b:ad5:18a8 with SMTP id r12-20020a62e40c0000b029018b0ad518a8mr23173784pfh.16.1605105344855;
        Wed, 11 Nov 2020 06:35:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605105344; cv=none;
        d=google.com; s=arc-20160816;
        b=haUEzsSJVFnw8md234PepC46nc4a9Wad++/okFKZoDGIpX94oOZpSAkGh7yVK2EroV
         f5Rr8Xa7Bca8iU1dCwm/olVc4bukgYoGG566cGPrMVMo9NP2GNYqujP8NvcVQZuFUfZl
         XEb7+nyB+tXp3VZb+ONdhdQVI2CtF+BQxSsQVD+tWnhgGIPofR/hRWLWbgJbM+YP2yaL
         5pkBBjZ1y68huGvi5st8Sl9rmzSF+CoLe0jgHG24VLwIiTxCmB9eAGP5FiBvxzQkzCRP
         BW80eVNT6vpwM4P3/Yfs92F3j2ob1TVDZZbSQeRRXtzIFEA8bCTs00AW3l2GLkHVmoir
         mnwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1v3v46143qlbHKcKxAQHZCqAVPerk8jpepPtoNSlpl8=;
        b=WR4clT2OTTbcl6KFHInDEcLGWZfumGH5rkzt66DEqt8fWvOwSYRoRBwFJ0UpOI2YZK
         oDIMiXedkZPDrP4R33d64gYxmC//5QUQ5VXOT48uKy9kCCo94vo+OrkcPBUFosb8vs/h
         9KFuztprT6d/7qXQtAl+8LkrTpjbreV+jw43BY0vehuGk7O8GTaWaXDqTDRlPu9Dp+Q3
         69XoAEKX8jMV7Sdn1yO5qeTIbmjUWP+a92erZCLMDiOI8F6DqUhyVXBCA17mJZ8RAM5V
         y1EwNdZpVWhbU+O9aI87DuoPtTngXHLKa9K2F7twvR7NdOfPOWhlOo88sgRdwdJ6qKrm
         TOZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kzsM7g5m;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id e2si30436pjm.2.2020.11.11.06.35.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 06:35:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id w11so1054275pll.8
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 06:35:44 -0800 (PST)
X-Received: by 2002:a17:902:d90d:b029:d6:ecf9:c1dd with SMTP id
 c13-20020a170902d90db02900d6ecf9c1ddmr21191991plz.13.1605105344448; Wed, 11
 Nov 2020 06:35:44 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <20201110145430.e15cb0e0d51498d961206be9@linux-foundation.org>
In-Reply-To: <20201110145430.e15cb0e0d51498d961206be9@linux-foundation.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 15:35:33 +0100
Message-ID: <CAAeHK+yx1dAnR9n7c5iWjXEQSab8V5xEW6hLwVba0cbc6rxvcA@mail.gmail.com>
Subject: Re: [PATCH v9 00/44] kasan: add hardware tag-based mode for arm64
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kzsM7g5m;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Nov 10, 2020 at 11:54 PM Andrew Morton
<akpm@linux-foundation.org> wrote:
>
> On Tue, 10 Nov 2020 23:09:57 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:
>
> > This patchset adds a new hardware tag-based mode to KASAN [1]. The new mode
> > is similar to the existing software tag-based KASAN, but relies on arm64
> > Memory Tagging Extension (MTE) [2] to perform memory and pointer tagging
> > (instead of shadow memory and compiler instrumentation).
>
> I have that all merged up on top of linux-next.  Numerous minor
> conflicts, mainly in arch/arm/Kconfig.  Also the changes in
> https://lkml.kernel.org/r/20201103175841.3495947-7-elver@google.com had
> to be fed into "kasan: split out shadow.c from common.c".
>
> I staged it after linux-next to provide visibility into potentially
> conflicting changes in the arm tree as things move forward.

Thank you very much, Andrew!

In case we need a v10, I'll do the rebase on top of mm and include the
kasan_enabled declaration fix as well.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Byx1dAnR9n7c5iWjXEQSab8V5xEW6hLwVba0cbc6rxvcA%40mail.gmail.com.
