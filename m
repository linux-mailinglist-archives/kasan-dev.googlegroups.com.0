Return-Path: <kasan-dev+bncBC65ZG75XIPRBUU77WRAMGQEKP4YWLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D5A0170155C
	for <lists+kasan-dev@lfdr.de>; Sat, 13 May 2023 10:52:35 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3063a78f8a4sf3864280f8f.3
        for <lists+kasan-dev@lfdr.de>; Sat, 13 May 2023 01:52:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683967955; cv=pass;
        d=google.com; s=arc-20160816;
        b=0uN9co9RkhHaXjHBlOMZreH8VtqC0zqSRi+UkbRWJwTiC9j9OF7A+bBJffe4FRHc5E
         RnTBZcv2Kkn1RcqdoTgdmYod2lnPQtB82rkFPw6EgaVmC2UrJeQEe6LHQjHKr6D70yGo
         YvjxB6Wd3UGRAmW74xl9wcKa11+RtgTWh+qIe13Dd4Ba8P3xrd2SDy1W4gr0xwlNNo25
         7FNPTeu738BMr61ORt/pffdEWrzv4YaCz/JEDLUseRpMiwzbYlku2Fm34UA3cuyXYQXj
         2/8gFXJR+Y/VBAT0gKYe5ZrdQgGStA321wL8BvTROdJDpa/hzVzmpbCIjF6JOC6DLGUE
         a+5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=x3lIHvO3TwxhQipifQXzeNs5PT+2u0kMDNgHxLRwcMo=;
        b=ELcDHTnc4LpW4ZKe15EF0wexP7pGSiVV6MtyjzB9OzKKst2oMrvCxwTcgKlO3ceQqw
         xKY9okpk6017Pujsipnj/tsS6wz4F/7dl6je13FwRiQgkrUn/hF/l2ypTNUfUL3LpqEL
         byxtPs5Z1zxdEy7oDmCF4CyTxGWAKt1WYpxGFGDSNqBwlXkyzewA5mqm/ZDaj1MbfRpN
         fAekBLIpInEqMPb54vXnspFumjDR6GnQUIj/4U7lfe6zhEe/6G/ZEOnhNF6GS3RXM+jJ
         W1sx6wqga5WsF0WOQGQ2Za2Be5EFR++ueXcZzzNktbOBZBIioXx6cRlPo5Hfw9IwHcHr
         E6zQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=EcwUA8+K;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683967955; x=1686559955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=x3lIHvO3TwxhQipifQXzeNs5PT+2u0kMDNgHxLRwcMo=;
        b=IK6w4ECuDUZODyBH2x82oFcQoz6DIB3gwq59+i82vXPLnViIq8Loskr8HmIOBZHlNY
         aKg3xSk9uHchDAAtXSLXpFSHUnX7FCVrt+BOZ7J4e9Nt6+MxXx+808qFJuuuDTz4N1FJ
         FcyuAFvc45GJPuVnU8s40S9+1p7zgr0RHE3yEWmin48bd4N7xM+oF31vDeX8Yz+jNj7o
         a712rMP8BVQDrzBvh9LFJ04y1jqOHdcf4wh324rzGmAXPmOfgGCxAUbyvxQn/AG8wFS+
         cotxdzzVZHRN4/vYdczA9gvBxJ51J/EUVdBSatc4ma+IIGZXlVQkRo4ytDLRSFdWjy8l
         XuNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683967955; x=1686559955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=x3lIHvO3TwxhQipifQXzeNs5PT+2u0kMDNgHxLRwcMo=;
        b=XHPhRgPRu9YF7lcVY/dq30IRRtcpfVL2q25rrLes5zh5U82vAzZojD8mjXxcppHL/6
         vW/PYdtBR2BxdPRuAcT0uLDm13FnhNiqBX8/56eCxNH5KSMOLXDw8oWLbIWbQO8mv0TH
         NB0DxgCtvpRezsEwZMecfr3SynfLi3U4oi/2Kze+qj0S3ixLrO8gauocJY5bW6R7o5bv
         r6+d5KnERyBbe271xYhiB0wG/Kb/S37wuKY14Cl122p4/tXM/X+E/BWgx03ZJ0FsiPx4
         ZNm7NlZ4qGCBzfTxgZmw7wwUddj4bXVgEqS7FyQORrrYv5RFewa5AsLW8b3he5DdEMJb
         Pl+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxgW/G5ABId2edJ3g0qglCvQUNuNHMQARnWPmDJLZTh89AmxRj0
	y/e1AtgBBpoRXW49ZTWqUSk=
X-Google-Smtp-Source: ACHHUZ6FqPg35qjhnNbBVVqyJc49zypWP11hZlcXYVD76hWt6ZovhEN9cShA2wHCNWQXXJk231wKlQ==
X-Received: by 2002:adf:e552:0:b0:2e4:c9ac:c49d with SMTP id z18-20020adfe552000000b002e4c9acc49dmr3647078wrm.8.1683967955039;
        Sat, 13 May 2023 01:52:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34d2:b0:3f4:267e:9f with SMTP id
 d18-20020a05600c34d200b003f4267e009fls1302128wmq.1.-pod-control-gmail; Sat,
 13 May 2023 01:52:32 -0700 (PDT)
X-Received: by 2002:a1c:f705:0:b0:3f4:f0c2:132 with SMTP id v5-20020a1cf705000000b003f4f0c20132mr4711695wmh.11.1683967952769;
        Sat, 13 May 2023 01:52:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683967952; cv=none;
        d=google.com; s=arc-20160816;
        b=BjmnieG16Gbdwa9OVhSl2WzSQNYDLhr7UtOyLP7UKejwN39Df0/MIEUOOmcuEbgnhk
         740NgL2Uu08G0ZI5/CYfjbtnUNWuj8G1egsNojFcHmQv5PZ40dr7k5XrX97DyLfwTjBB
         X4xPsgAj/j7G/O4sZoA4zplu/sJsFacL9NCfrfHVeXM5SJelhb/CbmnFJZ7/1fd3e/x7
         51f4FFre9HFcbzfXggCZrbnGo6CI6dob7HydME+scjQHhvgBDq3uDBVO/1PEwijPibvp
         7nI5eIzQfagpn7LbWwYB1O6PmjLC3EdtbknRaLywE2T6Wlp0ZrpDX+R1cq+u4lqI5mjA
         vAWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8MeuaNjeaikYWlAFObQpd6SYPmjzbm3/sLwf1GEc+RY=;
        b=A6QQ9PX2kdHMyyHV/8LStQf8jboZGdZ90bNkrAgxHlN8uY10zhiZgRryQH001u/ihG
         fclE8RlogCxpQudrUrOIEq6aEugGr1uY3MrGr2aQKxPhR3zKkXmGwfFKWkU35AtI30VF
         caTbGacnD8OMhOo8nHjibZeuBi+kKfc+cuv+6YAEXf4nY2Jlei/KTQJn5RWAJWMPxzyI
         UpZiMrvjyw5fUZQ8FsbAsXt67vutdcX5ONj2GyNKh3LZqB7yTQ9l/L6karr4SFdFJ7rg
         sdbyBrL8zca8oOv/Ezq8ynHz3TYKaEBIOCrV7wYKjLYlMrLfkCSWqEyWpSsWJ0KHpmva
         kwlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=EcwUA8+K;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id l11-20020a05600c1d0b00b003f4272db66dsi1160036wms.1.2023.05.13.01.52.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 13 May 2023 01:52:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-3f420618d5bso51643855e9.1
        for <kasan-dev@googlegroups.com>; Sat, 13 May 2023 01:52:32 -0700 (PDT)
X-Received: by 2002:a1c:cc0a:0:b0:3f4:1ce0:a609 with SMTP id h10-20020a1ccc0a000000b003f41ce0a609mr16031095wmb.3.1683967952310;
        Sat, 13 May 2023 01:52:32 -0700 (PDT)
Received: from localhost ([102.36.222.112])
        by smtp.gmail.com with ESMTPSA id j15-20020a05600c1c0f00b003f1738d0d13sm19249411wms.1.2023.05.13.01.52.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 13 May 2023 01:52:30 -0700 (PDT)
Date: Fri, 12 May 2023 17:01:31 +0300
From: Dan Carpenter <dan.carpenter@linaro.org>
To: Chuck Lever III <chuck.lever@oracle.com>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>,
	open list <linux-kernel@vger.kernel.org>,
	linux-mm <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"kunit-dev@googlegroups.com" <kunit-dev@googlegroups.com>,
	"lkft-triage@lists.linaro.org" <lkft-triage@lists.linaro.org>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: next: WARNING: CPU: 0 PID: 1200 at mm/page_alloc.c:4744
 __alloc_pages+0x2e8/0x3a0
Message-ID: <1059342c-f45a-4065-b088-f7a61833096e@kili.mountain>
References: <CA+G9fYvVcMLqif7f3yayN_WZduZrf_86xc2ruVDDR7yphLC=wQ@mail.gmail.com>
 <6c7a89ba-1253-41e0-82d0-74a67a2e414e@kili.mountain>
 <DC7CFF65-F4A2-4481-AA5C-0FA986BE48B7@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <DC7CFF65-F4A2-4481-AA5C-0FA986BE48B7@oracle.com>
X-Original-Sender: dan.carpenter@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=EcwUA8+K;       spf=pass
 (google.com: domain of dan.carpenter@linaro.org designates
 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Fri, May 12, 2023 at 01:56:30PM +0000, Chuck Lever III wrote:
> 
> 
> > On May 12, 2023, at 6:32 AM, Dan Carpenter <dan.carpenter@linaro.org> wrote:
> > 
> > I'm pretty sure Chuck Lever did this intentionally, but he's not on the
> > CC list.  Let's add him.
> > 
> > regards,
> > dan carpenter
> > 
> > On Fri, May 12, 2023 at 06:15:04PM +0530, Naresh Kamboju wrote:
> >> Following kernel warning has been noticed on qemu-arm64 while running kunit
> >> tests while booting Linux 6.4.0-rc1-next-20230512 and It was started from
> >> 6.3.0-rc7-next-20230420.
> >> 
> >> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> >> 
> >> This is always reproducible on qemu-arm64, qemu-arm, qemu-x86 and qemu-i386.
> >> Is this expected warning as a part of kunit tests ?
> 
> Dan's correct, this Kunit test is supposed to check the
> behavior of the API when a too-large privsize is specified.
> 
> I'm not sure how to make this work without the superfluous
> warning. Would adding GFP_NOWARN to the allocation help?

That would silence the splat, yes.

regards,
dan carpenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1059342c-f45a-4065-b088-f7a61833096e%40kili.mountain.
