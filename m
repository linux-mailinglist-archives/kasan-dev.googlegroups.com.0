Return-Path: <kasan-dev+bncBCF5XGNWYQBRBRPIZOVAMGQELRBNNDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FE007EA968
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:15:03 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-280152bfd40sf5304833a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:15:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699935302; cv=pass;
        d=google.com; s=arc-20160816;
        b=zmHb7UtnMwX2+yUGLwsCmm3AfprN0VBUt5eyBGTpD2jtBrDaBW6OEme7vXSM1mOw33
         XHBMUopa2o8vlEFHS0RAiR8g4pnoqrN/+lWoWnFuPlvraCSYCA7avf7ng7/Wly77F3RD
         9yTdYA85LZZMFJw5qO1EOUYumUmQS8ohIYkO75Dr3LxN9Q0otI9HzZdD7xCLWJhYUU1z
         H1McPNmqbRLGPJUzdFnzQXrBkocWQsiOAana8Gt5Ry5fkI24BhQp1twCXQZxeAQcs/B0
         x0cJc1Dy8OT+1WD1dj++MTFNDuCUVAlhu2Iq6f3oF3uTqGLzqYLweoyog0cnICPpxltg
         cSWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ePrEkohfUJgEoSnKaMzB13WmBqJzHKom3rtc7+ka/Vo=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=IHvsckjhax/PB+gp2VYzyMK6oxNxnytrxD+yiWv/XGP5cBju0wMBKw69jxd2IelWJK
         vEBen9RPh/EypECvXIT77pwuUkVEY2LfUbvXL45C73GW89kry2+akB0BX2RwkbTWEZn6
         OHzyKzQy99z6hAOndNz2RdtgIvY2vBjV5fuyVFs3LooELDAbgwOke2boRiXHRsi+NgDm
         lrVXbD2qrns8WJVPrMMXGlMwcNFZ5Rc4sqVnDvxGbfaB5PdHo/mL6+V4ozEshoNUawyP
         7oISJxusqfYm64HqbgXoadDWSrrB5ij+tofEcw0KSFP70aBte1LulcN38KqTDk5jVdlz
         b4/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BahvhLhe;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699935302; x=1700540102; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ePrEkohfUJgEoSnKaMzB13WmBqJzHKom3rtc7+ka/Vo=;
        b=h05hrCbRQpWwfaTgmBYCzRv/wSOqlPTOwGWtyIbrj+hIRC3lQtbzIiwPh6vfl32y+A
         KEBSxE7kVNNEAYYDy2xwFkitAa2OjvZfUZLsYG4MqYNvymcUhqd2o+cty1l8JQnWNVp1
         Cug8s4/CRUnAjaEDqjd4VpYA7iYyJeAbTvXHTb7+cboDe3iAbW7RylUeGwF1b9JemC4J
         KOhfGIy5e5+wkPSOQFK6OiCvxQoSmYuq3K/nKgc6q7eBzEMCTJEFZGRnpkH9JByRFdP/
         oM5e0tp9lFVacyk4f26YlfUdHq9aSDUqeElSGb/pRV4J5ln5H5E6FBd2mFZKHwJxMf6R
         d0MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699935302; x=1700540102;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ePrEkohfUJgEoSnKaMzB13WmBqJzHKom3rtc7+ka/Vo=;
        b=J2JRxQEJ3WVRMpREBAlrJyu5ihDFty+JUsU4lwl+CHpm/KUuZhEDPdhP0fscljCaQY
         w/o2zXU8fznn6YGwiLZTZXlx0ctRf+bL5fNTySHtS8E4G9Yf/nv4v8LnhZ78m3V6BeE4
         i2cIoESTAAJBmLvEK/9srENWkpK8MTH7dK7oCcEeQAxvUpPaj5Fj/ZzAA961bcrWCFwS
         yOXT5yipvsI6B3TmvcdsRsjS4yAbuSAP7VdxjsaEK4fNKW/aRak5QwAjnQyLShH5Onag
         bo9CAS34Y530IfS1w/vAwmEhVQNxXaeHKWp1V3V3Pznct+BjN82zkcOzKK/HePdJz64v
         oOOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YykG79poAnQKwNMkGVKaaarbR0c1Y37zt+kfSq3w0h9/Wvd0BFr
	RS6Ebyvh03jACHxkgDafo/k=
X-Google-Smtp-Source: AGHT+IH2Vrs8GrhCr94rp6yklzDgOnHtsVLd/JLBMYRatwjtQ4sgCkDz/jp2bz2RgzNXeD8vjAVMFQ==
X-Received: by 2002:a17:90b:1e49:b0:280:2652:d4c with SMTP id pi9-20020a17090b1e4900b0028026520d4cmr7147919pjb.13.1699935301834;
        Mon, 13 Nov 2023 20:15:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fb53:b0:280:8f13:2eaa with SMTP id
 iq19-20020a17090afb5300b002808f132eaals3109497pjb.1.-pod-prod-05-us; Mon, 13
 Nov 2023 20:15:01 -0800 (PST)
X-Received: by 2002:a05:6a20:3d1e:b0:17b:2b7e:923a with SMTP id y30-20020a056a203d1e00b0017b2b7e923amr7558793pzi.7.1699935300871;
        Mon, 13 Nov 2023 20:15:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699935300; cv=none;
        d=google.com; s=arc-20160816;
        b=XYwWJo2MDv3otMBuQxn1+gEoddV+tFO7SPXWpzPZdGcvF07mbz7eL3rFT5NKNL1Lpf
         IIMCGqn0+EGUFZlAxQjDDCnzaDtGmhWi1StS8wZbY1oV3HOM77u1qN7JzE/xmKv18zsZ
         nHT5JcK2HobGHPRLuQeXCi7NBP40IC/56Oh2dIZN61o+MaEF1wuRueFNkSVU7te0pBgZ
         9Lw1f3hqb44Bc9OgZ456x/DTAxHhFB9BWiyjyH9KLmQa0IU6BHt0Li+suwhbjFGhZGlg
         eprn1F7EddcUpjF2r0mlflnzDiF/M6gMP632E+zD9lH5cW1E5fET5Dw9SSxMmOW75kUo
         lxLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OUC30dXlQK5fmzms4eR9YZ2PZDBao2AfV4/azmUSi6E=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=fcMqaqAKejhUCbJ8qB+1cL70pm7usWSw9uQLPoGReApMvc3zmm8KmbEIXy2427hcS7
         kCTiHbEmED0SGF18/0ck/gntaMiE5tzPw9He8a7N/5hHpd3a2mq+kHJODFM43OlXyZmP
         CljiC3/bYmswqbYDGzTKWqbYmloRHNL4uOsv7AA3DDvp8P5NJu02dozlAvimN/rx6aZC
         9V9stp2jP1iKXbAzTHvS9hrXDn6MF4WSyYw18D5zxzZbzeGETYPo56PB78j0atViPDri
         0Oyv5p2UUz9fou+Rv3plZ0Psh14FETQUFwpx5wyuSHnq8u26sY18MojR2rq8tjW6FWqP
         fGdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BahvhLhe;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id o8-20020a17090ad24800b00280295eacd6si712679pjw.3.2023.11.13.20.15.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:15:00 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-1cc330e8f58so37670835ad.3
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:15:00 -0800 (PST)
X-Received: by 2002:a17:902:7d8e:b0:1c5:d063:b70e with SMTP id a14-20020a1709027d8e00b001c5d063b70emr1114726plm.53.1699935300585;
        Mon, 13 Nov 2023 20:15:00 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id iw17-20020a170903045100b001c9cc44eb60sm4799660plb.201.2023.11.13.20.15.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:15:00 -0800 (PST)
Date: Mon, 13 Nov 2023 20:14:59 -0800
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 04/20] mm/memcontrol: remove CONFIG_SLAB #ifdef guards
Message-ID: <202311132014.F03494F@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-26-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-26-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=BahvhLhe;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631
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

On Mon, Nov 13, 2023 at 08:13:45PM +0100, Vlastimil Babka wrote:
> With SLAB removed, these are never true anymore so we can clean up.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132014.F03494F%40keescook.
