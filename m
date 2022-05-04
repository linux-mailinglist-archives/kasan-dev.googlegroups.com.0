Return-Path: <kasan-dev+bncBDZKHAFW3AGBB7UWZGJQMGQE5HINVPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E0178519C37
	for <lists+kasan-dev@lfdr.de>; Wed,  4 May 2022 11:46:38 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id q6-20020a1cf306000000b0038c5726365asf431604wmq.3
        for <lists+kasan-dev@lfdr.de>; Wed, 04 May 2022 02:46:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651657598; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dy0JlR6SxQ13u+HtW9XOdb3DEss2EyWAJazevHw6QHyhbiyzq5/HYFYPpjr4+WDTq9
         DX9wLwPe47EHa8YRyvaD/zhCwZisjRfitMxz1oO29WAfI+1I79XIN7OFNfiEfJLgvCKW
         8dCfORGyPP8N/1NP4dJOWF8mqATMtMXGmJlfIC1me1igoCcSD/lMBcKcPIUX8pK1Olit
         2DvYGt989PMHqka2R5MNMeIadsl9t9B8KDakiMPIRFFcupeepu4KRG5k56Y8jEGbXS3G
         n25PZ54SE4quu0KThvz9dijn37XnfNo53N1CCVuRCjAfuKqnvRJ6Zqbz/WDoXoZ3UwxY
         5YGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=DEvkI6yOd+5gu+6dW1/WOE62Urzs+Gh1sTN464PCczA=;
        b=x9+eeIzkZ5iknCeVUUO9WY6p2S+A0QHZkCWwmX6g2XkAQLbcuzHrJyQZbpGpNYCcQr
         rqeKku9IntJjIG+gErfCod9/RxQsqRGCyma3/P32u8gPhdnZwRb2+9C7rEOptEnhmKYn
         aKFpFgt9StibQxBxupFor3ybWpWYc1O7qSp3GVFBsVFKA3OAo6oPB+Uv4Y8v8JflAgXa
         PMdPmEdRwMvQ40E3YgvKbTnVN6+5jlo4HpOnk2Q3KLTmaBGR0M1Kcl8y98H0D8MyhFtp
         TwoxvdtRUDqHjdt894WovXYX9oVfGIo2Ms2Fo+a4wHve8ssSaKeG7Ka89vEUZznAhTas
         Oz1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=DNW0smbO;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=DEvkI6yOd+5gu+6dW1/WOE62Urzs+Gh1sTN464PCczA=;
        b=icsaqiTGsS/s4koJEFOQWFjnw3rkW/htUpcZMyu2jkJjWMRxASuWKstGMuxkc6Ugb7
         K06HiHmydPzyxbR0MCtiHX6ztEGKZqVVdKPMMRZWhYcEYBmNhA5INQdBLSKEzVQYJOX1
         Fc9fuISRyCeDIzQ/ARTRXETmRwWygwciBPD9YSL8EkcFJcRvpu/WshfV6BCZsK2pTfbS
         Hq6eU1GQPTwEmr0gGPP4xbXkW7szwVHOi0Ele4UXqX1jSObP/J4CLfnVRinSBlVWjshK
         nYaSEXuLUvm8YacEcqFkQ9LYHYEIF6q4R2sNXaAkdiqXELsQUp+Gj3ikGfVWwMXhMJK+
         k1yA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DEvkI6yOd+5gu+6dW1/WOE62Urzs+Gh1sTN464PCczA=;
        b=1meMIM9fixTqw+/XchFyXmFY/FkWXsDU88txwmdQJ7SZdbXvYURZsx4us9s3CW4c2p
         M2MlaF5Kjzj2ttu1V5rVNP2Af+5CrUa9WMPQYFz3Z25wYhv5WodXH1aFiNvqzZLsTHzX
         o4fesjb56btZ7WnL/WsweRL+RSxT521uZaQz9ZudT/D2dS+QkARg/P9H8L33Xi3wpapW
         MyZvVGONf6B3vz6egdI2o0FohzLwTpsH70d6IMM+tOEFSTruabrWNQopBDGHIps3zlYn
         YZDjBUW3z2flWlVbGod7Mfz7UnrgYJ/Seusj6yJEsSfpAzAtMTwmiCDo7dfzL9Z+bG0/
         y6Vw==
X-Gm-Message-State: AOAM530/+iVAWWIwMEpiDnGlK5mxDPaKlmUFyUdOX1rJjRnd3O/g0d1O
	O5EP6WepU4gZRHrF1fBSC88=
X-Google-Smtp-Source: ABdhPJyl4erYj7wek09esBDlcyThpbA6a9jRcTDLoyaoOcy0jmNepnODhOlNv/OpuKiIRPtBs9qxGg==
X-Received: by 2002:a05:600c:214e:b0:394:31c6:b66b with SMTP id v14-20020a05600c214e00b0039431c6b66bmr6932938wml.31.1651657598606;
        Wed, 04 May 2022 02:46:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1554:b0:394:2902:4a46 with SMTP id
 f20-20020a05600c155400b0039429024a46ls372393wmg.3.gmail; Wed, 04 May 2022
 02:46:37 -0700 (PDT)
X-Received: by 2002:a05:600c:190b:b0:392:95b8:5b18 with SMTP id j11-20020a05600c190b00b0039295b85b18mr6862987wmq.152.1651657597651;
        Wed, 04 May 2022 02:46:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651657597; cv=none;
        d=google.com; s=arc-20160816;
        b=sdf4E/ux4DA78u8KFqnlUDiQAbjb0LRwNu9ZoQ8JZL7CBfMWAmpFGKmIg0uMByw9p/
         RimD50f3DwCqkE0yRT7cueFHzeOtjNQ/sUCvN3VxI0JltoKYLp3DYmigTaERuXkTDFDL
         VgKyhaUstbBegT+ltMaTlRfn3slgK9/1HQkVPSoGD/ObRqjk00rXg1+vWGBNyuz5xwI8
         gkVt16E2IdmgV1+VzcboJ91ez2xnsrDYDddt0pAlC3TMBN2l7ssKFD+KLUszIdJhxDpM
         h97Qz2RpVlmOIXfmOY/RTU+Okt7dTv02gZwIYKKYPKwpMemDsmeEaf95BE3MpL0fBSNm
         UxEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=f2BU3+t5DYqkYThY0d1gO61pXwUsjhrMxVTtLHPwDPI=;
        b=beBy5Fy2kWMCI1Sheey1QfLt/os9QO5TWwsPNhoFiqTs3EGuOAJPuVmLwwcHqcamLz
         C4HqAx4nyqitWB0AeDWzthFw9TLMkKnM63D3EkYmCsCKYFIV3MmjknqlO5McAlL/cwsS
         HJRebmWsyFXP7zabDf463bIWIrwtjTJ1LfPOCVTe2Fxd+ojeWQxzzbnHlKREK8vyOJf8
         mNhaYs4sp520HiboGGnPg4vXOiOzPxnBA7VUnMS3TdJqGnSBzLePeH7wVsgCSssSIBeD
         ByMmXa4LaIW4Rpb9N1LRGonQhEXbTA1r+8asZe0BeGwNoOFU4Ltwe1RvjCWgRYU9r0gR
         p5Xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=DNW0smbO;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id p22-20020a05600c1d9600b00393e98f67a1si310497wms.1.2022.05.04.02.46.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 May 2022 02:46:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out1.suse.de (Postfix) with ESMTP id 4CF78210DC;
	Wed,  4 May 2022 09:46:37 +0000 (UTC)
Received: from suse.cz (pathway.suse.cz [10.100.12.24])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id EC0192C141;
	Wed,  4 May 2022 09:46:36 +0000 (UTC)
Date: Wed, 4 May 2022 11:46:36 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: John Ogness <john.ogness@linutronix.de>
Cc: Marco Elver <elver@google.com>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Steven Rostedt <rostedt@goodmis.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220504094636.GA8069@pathway.suse.cz>
References: <20220503073844.4148944-1-elver@google.com>
 <87r15ae8d7.fsf@jogness.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87r15ae8d7.fsf@jogness.linutronix.de>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=DNW0smbO;       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.28 as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Tue 2022-05-03 21:20:44, John Ogness wrote:
> On 2022-05-03, Marco Elver <elver@google.com> wrote:
> > One notable difference is that by moving tracing into printk_sprint(),
> > the 'text' will no longer include the "header" (loglevel and timestamp),
> > but only the raw message. Arguably this is less of a problem now that
> > the console tracepoint happens on the printk() call and isn't delayed.
> 
> Another slight difference is that messages composed of LOG_CONT pieces
> will trigger the tracepoint for each individual piece and _never_ as a
> complete line.
> 
> It was never guaranteed that all LOG_CONT pieces make it into the final
> printed line anyway, but with this change it will be guaranteed that
> they are always handled separately.
> 
> I am OK with this change, but like Steven, I agree the the users of that
> tracepoint need to chime in.

My feeling is that the feature is not used much. Otherwise people
would complain that it was asynchronous and hard to use.

I mean that the printk() messages appeared in the trace log
asynchronously. So it required some post processing to correctly
sort them against other tracing messages. The same result can be
achieved by processing printk log buffer, dmesg.log, journalctl.

I guess that we will only find the answer when we push the change
into linux-next and mainline. I am going to do so.

Reviewed-by: Petr Mladek <pmladek@suse.com>

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220504094636.GA8069%40pathway.suse.cz.
