Return-Path: <kasan-dev+bncBCF5XGNWYQBRBRHZZOGAMGQESS2WJPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 674E7451EFB
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 01:35:17 +0100 (CET)
Received: by mail-ua1-x93b.google.com with SMTP id x17-20020ab036f1000000b002cf3b54847esf10340320uau.15
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 16:35:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637022916; cv=pass;
        d=google.com; s=arc-20160816;
        b=x20BIGpxXlrSKwDik3OZXGmu5hZXM5YP+NPk3OTqhTMriSle0S3MFSl8j3OEX1NG3n
         AHpAEFD11lqYEtXedi3gFFIDtp+nJ8DArLT5uwKYIcMVuS/rZCkPtvNAIZSNS49x3ZMH
         9GpjnfSuzHUrk9AWE6LpDFgUkoIZXF/7k/Lf17a9s7ISobzzhTTzBwpEEf9axA1s99kk
         ombUsg+zUBxD5DsNbjRPKoeUG5xZBJ1oMKueADdaO3fu1IjVo4BvJBVrE/Mc/gb5PEh2
         BTGikVY9YpiEvT3AjkDOR2ppLg8jyFsXU2XLSzJwgA/z9eI76zem3QufHTPe+Tjh3dHe
         JgtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=C1lYDQv4HUNnwO0egPuoyC/gDQOEGvbV3ZRpbTqhvtU=;
        b=UzpXajP3vqOcDbt00CJJG+ux+fwQ4psMnC5abzslUHBPoV0xn/Hdiun3JlmcW3siiX
         ytQkiFDykshPxk0MxzZoMUkOudFcarxE25Tn+j8NLj619PBW5Q/e231lkr//dSjfNXiv
         iHxILadQOLNt3gnwQ5zxSpbA7yDAREpz4XKqYB6isMxj/f7VPlkxA/E1ucZcjErzc/k8
         Gf5m4Lwou1ZLE5M1m/vaSrdFIlpOaHDsTUkU+5RkFgMz3tCwlojpOM8rxu9Nx3SrNHLz
         f+LohTtzxWptJjO5cyt/DcYMJlfbR3LmLudfFHWc0ZZZ8Q/6ljj+/b9alvPy6hkGcwHy
         9G8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=kRgsOovb;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C1lYDQv4HUNnwO0egPuoyC/gDQOEGvbV3ZRpbTqhvtU=;
        b=IsHMt8UVOQwoUUpP477/hHEG1E5px5y6CjNN0gcZbpDsrGyVvReHPIMHcKWUvGGo13
         T6H2Of2+u71DvKD/5jp37tmfnKHfrKHpD7IGeiYjKKTP8cWRQpasOlzIdgTIJWojXHSw
         yOngvbGKPoWLoV7z7PGkzCmKtnlAKBgM0yZ8o1NaxO7+DfoQbWBVxI96+zwWTyxqt+iu
         wmktNJcMbDnTu/aTBqMv+1MMrFdQw9fMsg+Xtm4kXOCHYLFQsmb4du4tUYK9pW1PQWCz
         qZ6OfZDNuNs2eXA0VSBzx2ZDAwUuut0JvSfVymnSnz0UgOhReijsxsCck36ReyHJtHh6
         vpPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C1lYDQv4HUNnwO0egPuoyC/gDQOEGvbV3ZRpbTqhvtU=;
        b=tyNDwEvN5mAMoeu27GkrkFU/JqUENWRIqo4HBQSYY1uQKBHIvg2T8Kmx0D7n0vsdM1
         E8mc1Me6WrVsd+b+sEdsseJrFEHj6adm2lfBrQn70Pc5WV0cbWEX86Xf/E0PGPprQ9R3
         qmZZ4VFjFCAFhtt2mCpQTitUeFA6ymHczpuMXAMON7c3/3JnV6O8qiS54cBcGqJqa0th
         n+C2kN0nO0WB7AnY4e1FGYf0RRKAGug8l/YCJB/CTejmrhraq5NqtCm8s5Bh8IEcDdYj
         dGwwueM86YezU2GsdX5kkFlMFB91wh2dlf9/TtU3d7AO6/tpb3QP0JfZO34JPqIQTzHh
         k5ow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NexPh8kWnxuQ+mjBQ/ChGFXd6te9d0IF7/MyDMQNpi5fAzlkQ
	HHmGwBHyhzU42HgKSfT8POA=
X-Google-Smtp-Source: ABdhPJxr3P8czVjYYwFzdY4qvzPS4lxm7CPVFUDfpCQ0IGIAjcZ7m/0vwJsJxZSNK7TBtagdhhYuWw==
X-Received: by 2002:a67:ab48:: with SMTP id k8mr49365245vsh.30.1637022916128;
        Mon, 15 Nov 2021 16:35:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f415:: with SMTP id p21ls5481498vsn.1.gmail; Mon, 15 Nov
 2021 16:35:15 -0800 (PST)
X-Received: by 2002:a67:e15b:: with SMTP id o27mr48246664vsl.61.1637022915685;
        Mon, 15 Nov 2021 16:35:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637022915; cv=none;
        d=google.com; s=arc-20160816;
        b=DEwbNQKY8yiGWBZyXnL0hEB78m17DmS/rwVJe6E9YE6yM/L5IJbO+M5OQmjhagKTlb
         lNkvrEQWUtrOyiWQikwfkh/nDiAKIdAzgvLkhO6fA0UIHR4nZqbOTvJFj0s/RUsNE67w
         /sd+oQRp5CRWQ8e30cmRP5XQ+D/J7n1XtZZD7ExilYZRqIy5CMLO1tstUf6FbiN7ZNyu
         DA57X9EpdZgB2reu95mM8PpBMzJ+irRdNR/DAYCObeC/HCdy4zKCdYqodCKI6ZyKC8DM
         LHnvhEQsaNLNuU/uh3fi+krUcs9If8JL0w4oHzBYBD47UmJUDt4uvCgUDA9mWQOSwfVC
         CnXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6YrJDwz5lHylUrRKBiCCXn7XIadwbTCaDNmr8F8Qv+s=;
        b=p8R+8Z3O3JKSPWTo/PNeW8JjCYrUOGcCcKs6yD8nxGB4ohGdmtYx+PfGWV+vzMfAaG
         r/56jypm/BcadI1RdB5fzADVq/FuOPkSQTqqhBmUM9ELrZz5j9E0a0nZg6RNksPTgwFM
         xv30ipcYtDJLyRb+xlxHYC4bzvWCLFi9axNfTa3gMtBCu0mSt7Uug0px+N+8lqBgwTPo
         bhEJTdBDG/hDbmBg9wsXWuDUGmdTFSif/WI+KDSLFt69zx+VB8D/WgunteH7WpRv1iy8
         albmb6ftl/Y6Fx2evXtJZ8ALvECCCy8Vp4Il6T3zWHLXSEoCag+2OG9JZY+pgDe7XmQa
         3rXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=kRgsOovb;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id v5si902045vsm.1.2021.11.15.16.35.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Nov 2021 16:35:15 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id n8so15897648plf.4
        for <kasan-dev@googlegroups.com>; Mon, 15 Nov 2021 16:35:15 -0800 (PST)
X-Received: by 2002:a17:90a:c398:: with SMTP id h24mr3495024pjt.73.1637022914921;
        Mon, 15 Nov 2021 16:35:14 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id s21sm16292860pfk.3.2021.11.15.16.35.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Nov 2021 16:35:14 -0800 (PST)
Date: Mon, 15 Nov 2021 16:35:14 -0800
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
Message-ID: <202111151633.DE719CE@keescook>
References: <20211115155105.3797527-1-geert@linux-m68k.org>
 <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
 <YZKOce4XhAU49+Yn@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YZKOce4XhAU49+Yn@elver.google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=kRgsOovb;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62b
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

Ah, I found it:

http://kisskb.ellerman.id.au/kisskb/buildresult/14660585/log/

it's actually:

    inlined from 'kasan_memcmp' at /kisskb/src/lib/test_kasan.c:897:2:

and

    inlined from 'kasan_memchr' at /kisskb/src/lib/test_kasan.c:872:2:

I can send a patch doing the same as what [1] does for these cases too.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202111151633.DE719CE%40keescook.
