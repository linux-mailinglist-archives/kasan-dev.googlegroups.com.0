Return-Path: <kasan-dev+bncBCF5XGNWYQBRBTXXZOGAMGQEL5Y47UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 00BDA451DBD
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 01:31:12 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id v19-20020ac85793000000b002b19184b2bfsf10469202qta.14
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 16:31:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637022671; cv=pass;
        d=google.com; s=arc-20160816;
        b=c4Lp08nBYN0XyevzQIGFbmVjGxcDdXfj8hfstMbybQ3FLKFEBIq0cLerapF9lXXvAW
         59Vfg9ijhemfNtZjToF8RJE0HgpxUG1LO11KD7caFoyQQ0IOhv9GLQlEJLLAuwUSADwA
         fAoepVMaQobINROfpHY3XE3C19EBngg+j1pxDN5NrzlUXIhOdAOZk2MrCRqf2CHpu0UC
         Ug/U552wfERiD1MydemVL6Jnm+wibElwiBieF0v+ToDbJ8ogrL1sngjq0KfdksAA8Y9S
         nBt6ZPCjwCtGsOtpHx/3AE7MaIu3V5/uR8Y9FXFeolHzum64B0clzU4R5+9d8XKdus1j
         dGDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tF5rYCVV81VUJ85Tmi2UE0tdGyucIKu0/faqlXhdn+U=;
        b=Y3MAO5EIJwwXlJAjFEPhjv+i40cVGIiojTftQEtJENuxBSZVzKqEDqPb7sk/atCdHe
         oK/naxU9JNwdqQ1gOoYOkI8j9UwieknmsfYo8anVs5QC6QveYmIF0h8fq7aFgH2qpRCa
         xVJt7nGaeg5nuAk24OEW/J6dCa0sHkNK+4miDkzfbbfsohslRdmn83hourKz5KRaOgdy
         lC2jutKaR+tvfaF7UeDrQc/S4pJz344PuW9cJs80j09d7E21p4bLKI6kh9P1LFbZjD/w
         ftLHOxQ0Jaa9UDy7pnLP6xZgvA74+BJiBjFMngeuXlRCmrJPNSKqTIXWB/c+McJAZ6tq
         0Mew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=jkN0+anU;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tF5rYCVV81VUJ85Tmi2UE0tdGyucIKu0/faqlXhdn+U=;
        b=rw1gmr9snt4BXj/TEC2f6T3az42W6BLO88f2o38hgdMGIuxJAA8hTpdUFZ8gGCD7V0
         Y2NTomHDGVFqXuxc8CVCAHlQf3xKy2t3k6Dm1cy1k4jE8VHspCVFuOYZMxah+nneHoFg
         vmif+5bAu1P9lU+6x1B+up3mIb2+syWHj5oK3ksV509MvdLrj/ZpGjJQIZwrvTTRCeDn
         vC13BfH79IYXiicG+BC6uVHMxvHO+FUxUrGIGK7am8wd1kX8VlJ6n7vYpAtIKYQ42lC/
         USYhExuGYeHNY6BTycgL9ftvJ6Y/XIb0ZzFmwKY5k3DUMldPIu63YiTFEuxCYVOI9stC
         Wsew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tF5rYCVV81VUJ85Tmi2UE0tdGyucIKu0/faqlXhdn+U=;
        b=CWODUtQ3fq2bCqRptJ5ScztgPitbSxz6z93NFRJh7qZJmpzZNKfNt2IxFEVkhxC42U
         EWgle7Ac7oXnXRvlejScaZv/etyAzrYW6oPuQsX7YxXYzXTOXuZRa/t8DSQWXmNFaSxT
         M67+ItLDEwCSk6ZcZWBXlUx1ejTXi0XNLri3aaHLv5tEDVau7eUuV3lF/uVPyXfWcPeh
         koYvgks3AdRucx2V/tjmUWI7PN6+MVt9bdYf7XRFVUkmPlZzKdkZXRjNoRdp0w0SsEli
         8OItw1W7N5XCWz4fQLX5p1TJJe3+Tg6/c5S1YWS2Ces2owCkNjaR4TgLAjpyt926PNpt
         enQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533iuleCfm+ISGGcqaJZ5fIxhbFMSK/Ve4o3BvAJSdZfyxJ7Kj/9
	dmsjh30Lu5bYRhul8JnNbFA=
X-Google-Smtp-Source: ABdhPJzxvZlcwlMqCTHvE4S1MzG9Xsbx9BaIWk38Q79kZN25KmakgKODcWmiuU0Dh6QqLylylAqEEQ==
X-Received: by 2002:a37:8946:: with SMTP id l67mr2759744qkd.519.1637022670898;
        Mon, 15 Nov 2021 16:31:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f00c:: with SMTP id z12ls5173350qvk.9.gmail; Mon, 15 Nov
 2021 16:31:10 -0800 (PST)
X-Received: by 2002:a05:6214:20ab:: with SMTP id 11mr41264488qvd.31.1637022670530;
        Mon, 15 Nov 2021 16:31:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637022670; cv=none;
        d=google.com; s=arc-20160816;
        b=TAHAnnUrBIJ42pBtGp8bUcSLBYPeOPUwJxh0EhmCMeQsAz14Y2iaPfO2QG+HCEAn+/
         jBl5A0OlW2XJQT1gOfNS2LFMIdsbrILTusxXLhG6kGWvGk25B2wivYeImcOWV92vl/69
         Vdz7oJVZ9jLboQ0lGFW+pJt6ft3lgNHEOlYcoVIMTuA1AcgdEao9G4OP+GrySseffj0g
         gBXsh1UxQv1q8mb7nkGqJtQIbsrbtJ4Qw0rnV06ib7T654fKe0zj1e6IhBVRu4i2dplD
         KpQgkvKHbFOw+oMjqNEKVYup7rkLlIhFQnoEmv4swSqL5Vl7eFZP5fDpdBbNcwFI5IvK
         d3YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zUAbk3pYDxq1bSuJItD74NAh/MbYUz0fiMi2jjsqIPc=;
        b=x7wW+VlM+XON63YiUS/1bRjg5kJpUEFIPG6lRJb3EoJcmLr5nUwSnUibC72y9qdXMI
         Kwp0pSrF5e7CPve7YmMAqRBFfvw81A+BeFHW6uIP7mWUaM5NMlwOjsq1jT7nGlpcsqWB
         sAt1pQRHJ8wXOARJXA005ooFOxdeB12Y97pNMyKulYul0waUbGIZFiC9hdFSp7wM1fs9
         xr14uaKAi4ONoYSU9/ZrFKh3zOtMnqUhrfoQr7IharM86/gLqEbsloQ/QJy/nele9FlU
         KFeoc9wthJFpLzhPO7NC+7HNQbtKOe3Ow/nVQW2KUnd1hVLKZ0dcT2neXysRS0QuhXn8
         t5kA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=jkN0+anU;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id n20si158795qtl.1.2021.11.15.16.31.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Nov 2021 16:31:10 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id r130so16513254pfc.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Nov 2021 16:31:10 -0800 (PST)
X-Received: by 2002:a05:6a00:1945:b0:44c:a955:35ea with SMTP id s5-20020a056a00194500b0044ca95535eamr36094903pfk.85.1637022670112;
        Mon, 15 Nov 2021 16:31:10 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id h21sm12755848pgk.74.2021.11.15.16.31.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Nov 2021 16:31:09 -0800 (PST)
Date: Mon, 15 Nov 2021 16:31:09 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Geert Uytterhoeven <geert@linux-m68k.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Nick Terrell <terrelln@fb.com>, Rob Clark <robdclark@gmail.com>,
	"James E.J. Bottomley" <James.Bottomley@hansenpartnership.com>,
	Helge Deller <deller@gmx.de>, Anton Altaparmakov <anton@tuxera.com>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Sergio Paracuellos <sergio.paracuellos@gmail.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Joey Gouly <joey.gouly@arm.com>,
	Stan Skowronek <stan@corellium.com>,
	Hector Martin <marcan@marcan.st>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	=?iso-8859-1?Q?Andr=E9?= Almeida <andrealmeid@collabora.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	"open list:GPIO SUBSYSTEM" <linux-gpio@vger.kernel.org>,
	Parisc List <linux-parisc@vger.kernel.org>,
	linux-arm-msm <linux-arm-msm@vger.kernel.org>,
	DRI Development <dri-devel@lists.freedesktop.org>,
	linux-ntfs-dev@lists.sourceforge.net,
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
	"open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>,
	linux-pci <linux-pci@vger.kernel.org>,
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Build regressions/improvements in v5.16-rc1
Message-ID: <202111151624.91EDCFF7@keescook>
References: <20211115155105.3797527-1-geert@linux-m68k.org>
 <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
 <YZKOce4XhAU49+Yn@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YZKOce4XhAU49+Yn@elver.google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=jkN0+anU;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Nov 15, 2021 at 05:44:33PM +0100, Marco Elver wrote:
> On Mon, Nov 15, 2021 at 05:12PM +0100, Geert Uytterhoeven wrote:
> [...]
> > >   + /kisskb/src/include/linux/fortify-string.h: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter):  => 263:25, 277:17
> > 
> >     in lib/test_kasan.c
> > 
> > s390-all{mod,yes}config
> > arm64-allmodconfig (gcc11)
> 
> Kees, wasn't that what [1] was meant to fix?
> [1] https://lkml.kernel.org/r/20211006181544.1670992-1-keescook@chromium.org

[1] fixed the ones I found when scanning for __write_overflow(). [2]
fixed some others, so it's possible there are yet more to fix?

Taking a look at Linus's tree, though, the "263" and "277" lines don't
line up correctly. I'll go see if I can reproduce this. Is this with
W=1?

-Kees

[2] https://www.ozlabs.org/~akpm/mmotm/broken-out/kasan-test-consolidate-workarounds-for-unwanted-__alloc_size-protection.patch


-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202111151624.91EDCFF7%40keescook.
