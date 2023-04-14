Return-Path: <kasan-dev+bncBDZKHAFW3AGBBU4V4SQQMGQERVYMO5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 537616E1DD7
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Apr 2023 10:12:04 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id c4-20020a50f604000000b0050508de6f4dsf3511988edn.10
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Apr 2023 01:12:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681459924; cv=pass;
        d=google.com; s=arc-20160816;
        b=eR+T9sl8jrVY3IMazGv76LIJsvyLBWktcUq9c8ROVIMLijRavP60DJisEj9H592h3N
         cU1DYj9/feYAiyC0T/ajgN6Dds8EdNXOaPpqx/tC8u44GCT+P9Rr/oGuAhi1TzkAgk4T
         H0KLUNDGABFPgaXUaoMjaAgoyUYgBEjM23ROVjTDtD5GF/Xg1OP+jv6SQGuOj4yYTWnH
         5nHx/OiX0eQpKbm2vqLUI1GDYTSdV4ydoN/Yvaa3eNsJ0wMV1EfdYVFomqZBsglBb/yQ
         3RVxjoOzffgS1507fWziROT/lk6Vlc4cz+APvMNnwmPrIds4942VaZlGdWl89vhnV4g4
         in9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yKWpQXJIlt1xOyRf3eui+cHiq9hVlh5EUkzCehgnuZ8=;
        b=bCwYyeWEOixCrH1EGoor4R4KC469MVfNmxmSf1Pxg6bLCPKdDDSyzyajqgcNlnushT
         lgfF1WcGYsQnolub/A6htq/ut6IyYXWPVozuBV9iyl+K4meCbsyopyEqYwsbK4CuZ4hi
         QHwXDrxVStOE0Z4KZclIbTVDr8xzOfc+0fPtMhTrqN6UKjQzvzn8LN5qxJa4J59DHNTt
         FMtlkhriMnipqcbUfSSFuBysIU0yuWEoDSWb4jzZcUqR/NClTbXuT9vvG6OceWDKEtAh
         Y4VK4502kewyvJUA0aIlTxIbM5m4hXZow8vaHG3nxkLe23LhGDURAA169Fv1gdbVFTjK
         e+Qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=iwTPtsV5;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681459924; x=1684051924;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=yKWpQXJIlt1xOyRf3eui+cHiq9hVlh5EUkzCehgnuZ8=;
        b=eu8BF+eCNn3vaZFPnMWmSlvn+gGB0y8NGJheyE4OccpySEaRQA1Z3Pbr1r+Xp3MWBW
         ayIcCWv6rzSo5nnQxwOTHceUvyrcXmUaO/SJsIUKuFoVG/Ee+9mEKvJQ3vxAo1n2WG4e
         KDHFpC21c9Iu1ht+Zdd4jbwj58np9h83/gHfSeCkPZ6HnKs/EB9LEW1YuP43wzPRskYl
         4Gm8xShDSMNAkertFqvZrxoYe1AwW6oT9xG9C+/XW8e/3YpRGYjaGAD+tcIjt84Esr57
         4aaG7cZpsxyrkohxDaUCFk7wJT69Z3nUO3YBSKc8VlU+Pjyr7kvdLJ5xP4LJyGCG6iTa
         kMtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681459924; x=1684051924;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yKWpQXJIlt1xOyRf3eui+cHiq9hVlh5EUkzCehgnuZ8=;
        b=YFcpRDHpSLs+6VrDdyeVxc+bC/eFrG2xl7ssXWEu8WOb2tDgjqgAZFDFsHiUDgDibz
         izLIKpoRgDbiCFJAbbmlsfMRCaUzhm3RDVkVt0ASBIoEdtfJUvbiEaCxD6slmUmyX3+n
         fg/L5sEk7XeUcsfQO5we8WtiN7vKnyhB5KwatWcRnhl/mBmgGnq8V9AIXnAiOBuT1bu9
         P31WgrDOkwq5k2RniNI40oONaVsofrJJggXccwmLqGhZUNOlUvWKX997O7sWqIBEIHKY
         vt4vh2ogA7qswNqUmR87Ut/RdeaUS/PyquFRxQhaRC7x+fUev5ZDJAFWgCJMCfWx26wX
         f/OA==
X-Gm-Message-State: AAQBX9cRBmAloWVKDJkMvQQSWvuoI2/JJYPrxtwE5Cs8zynmNe1aR/g8
	PmmQSdbNqlxM7RPFhtHfWwc=
X-Google-Smtp-Source: AKy350b3suyKMzygsRIs9EBOYWIhkflBv0hogLjE4SHF0+qK9X7mpimvDjo25PAQXqq2Sp3mVvPAEg==
X-Received: by 2002:a17:906:12cd:b0:94a:5bad:44ef with SMTP id l13-20020a17090612cd00b0094a5bad44efmr2776039ejb.11.1681459923565;
        Fri, 14 Apr 2023 01:12:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:371a:b0:94e:d85f:f87f with SMTP id
 d26-20020a170906371a00b0094ed85ff87fls1205645ejc.8.-pod-prod-gmail; Fri, 14
 Apr 2023 01:12:02 -0700 (PDT)
X-Received: by 2002:a17:907:6297:b0:8aa:c090:a9ef with SMTP id nd23-20020a170907629700b008aac090a9efmr5685377ejc.55.1681459922141;
        Fri, 14 Apr 2023 01:12:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681459922; cv=none;
        d=google.com; s=arc-20160816;
        b=uqcwB5+/XiB2UzbgMECAaEbD1yZQGK+Uoc8U/Y6N+kRFVwYszs8Xmaw2uZrysZEp1n
         1IYXQQzHtLGQwBsKl/FZ8pccXi5L8Wl7mPiqmboEo1zjCyNLItiqemvf9nne6/qI+Myc
         b7VO4UdgqDKYoeqQcwj4NVWZYtVaHhz9zxsqIpyV322clkjzbTk6QLKgxcvldSbyNRR1
         bGC3LOEwQguodvFLtT75M4LycF2d5r8ljH0vP4BeEyrrRC010ey0sXpy0Wp1wL3cRNOf
         /Ssi95n9kwS//6ff3jzcuHpCdPjmpT8WEbIv3CR2vEbFHlktsPq/TBdLvNdmE25rpg4i
         /tCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=b/O0ymfBIYoLmIJ1onnswDyLlhMcwo8UOm63k2V8FeE=;
        b=I110wMb69tOKXoEcn6MwcRuP/Z1ZgMllWnmXvWpPKZyik5/a+j2k9KNsLjPEB533QW
         7sKgbJI9NEeikT+nHK/g13SX9KxtzMH9ccfLIEEEcxWwkcY75o3dkr1tBm14k+wZXeJf
         BkBCDBp1uussdckVvm2c+VhN5sGHjBhn8D4gVBZ40gUje/+BaLa1isv0NAl+4LsS9zK8
         lbNDfoKiBpmuvVcTze/4R4VAt43OyQurZgjp/Kf/qbh5ztujP7/0Fu5BtVjXswX7SZSF
         HSDZeMPotakFosOrVR2PhVLbdMIv2dbn8FE3an4ZXvsuFsvrqx5FEbUYQGBFOqnnT6qf
         WQJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=iwTPtsV5;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id ti11-20020a170907c20b00b0094e847b3512si225356ejc.0.2023.04.14.01.12.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Apr 2023 01:12:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out1.suse.de (Postfix) with ESMTP id B53BB219BA;
	Fri, 14 Apr 2023 08:12:01 +0000 (UTC)
Received: from suse.cz (pmladek.tcp.ovpn2.prg.suse.de [10.100.208.146])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id E43662C143;
	Fri, 14 Apr 2023 08:12:00 +0000 (UTC)
Date: Fri, 14 Apr 2023 10:11:57 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: Pavankumar Kondeti <quic_pkondeti@quicinc.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	John Ogness <john.ogness@linutronix.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: Re: [PATCH] printk: Export console trace point for
 kcsan/kasan/kfence/kmsan
Message-ID: <ZDkKzQCM1gJnVBdO@alley>
References: <20230413100859.1492323-1-quic_pkondeti@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230413100859.1492323-1-quic_pkondeti@quicinc.com>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=iwTPtsV5;       spf=pass
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

On Thu 2023-04-13 15:38:59, Pavankumar Kondeti wrote:
> The console tracepoint is used by kcsan/kasan/kfence/kmsan test
> modules. Since this tracepoint is not exported, these modules iterate
> over all available tracepoints to find the console trace point.
> Export the trace point so that it can be directly used.
> 
> Signed-off-by: Pavankumar Kondeti <quic_pkondeti@quicinc.com>

Makes sense. From the printk side:

Acked-by: Petr Mladek <pmladek@suse.com>

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZDkKzQCM1gJnVBdO%40alley.
