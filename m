Return-Path: <kasan-dev+bncBDK7LR5URMGRBHPU7S6QMGQEL5PUFBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id BC186A465C4
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 16:58:22 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-38f55ccb04bsf4656885f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 07:58:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740585502; cv=pass;
        d=google.com; s=arc-20240605;
        b=ETmml7XM2bc1SJN164i5SIC9cNI1M1l5cJwaYzs5Gi4NAPP0ByOxwSXj8jCx3eT66j
         HX9vkAzMdhYNpeI7d4hM8pbA3CZYzLIkUuQPzeBnjpmECT3EHC/Y9ovm6HER4MnTBpa2
         zOiurZQn5+k5qk/mZ4TxLiFEESzrEHB6G974GIRN3yp1DVZEpgKoQikFJ/7RK6dRhCwQ
         9RhEAtjG5luFcakO41bp9uIxZANKEIFoSlIuWu0wZt12ZL1Vk8cOkYHYRv6klNKzgM/5
         fwBcAeCSIjU9SUAHo3CLU37ySD95XGGzJ9Al7RfxbD8vm7+BLcvBGIaLwNiQe4WeMN0z
         9SLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=SyeASWI4oqcBy5VOAJBwwwM7P7aYnUdkASETzUwHuqg=;
        fh=G2oDeEIQzQWtJNQ/9hC/2j7C+vBcOZN8MGWggH43ivc=;
        b=giIFew/0Y5tIAqgquHuo6yHiV8irQHoI0CByFv0EtlaWXTCHiZTVI+xTB9GqW7j04V
         zSlb34v/7Dwd2PTFV1Jop5GuPKHPgxyvX4z1d2zZM51dm5wmQihgUiFgMYHXTnDVHbIm
         6drlNTaYdwX78bSHnueqCQfOksgoHWRTecubntNrYKha/KJnqtLsabdH5811MeO3yKKf
         cKpK3dBr7xw80+u0l/6pY0BZuanLEyczuO+bi9E8xHih6cirAvOG+gDjqh0V8oFY6L5j
         HDWfHR8I0gqj+Yd+8zjzwgCddSMuHTE5VuoHnuYWqZa6fWzrO5O5kmVPcAoQo/t+qfA5
         /dfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eYUovpnL;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740585502; x=1741190302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SyeASWI4oqcBy5VOAJBwwwM7P7aYnUdkASETzUwHuqg=;
        b=aXib6B7V+s87QcP+aMkVYsMc6+u+eiF82KffUkj5ywnVTrIyobP0x/f3xS7oDQczro
         T6YNjC6hScVZwdgf2/pb5niYA5ZZDIjyo74ZDT67WawLxmdga7awMKIqDGavCAxlEm/F
         XLG5Uog6EXwDWzSxz02aLWv0KUFxgutbC9kv6jJhPc8nD2NV/mLB0dEtXTWCSN/tT6eT
         dzzVVZWgNxuWvQiikxAI4gHOy8J2Nzm/Re1of4bZRHRkMifyj3NaQwMlydhd3W1bYkYH
         41daWkCwe8dizJhexszt2mIbzNynrPNWRvx5BbQVrZ2MQeTDcOp4FF4uaT80BBPNG+mp
         lP2g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740585502; x=1741190302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=SyeASWI4oqcBy5VOAJBwwwM7P7aYnUdkASETzUwHuqg=;
        b=dUY+hX4fhbrsAEItQ/zzoELVLgb9BrKIcXLO38pgtGBAZDQqSA9b440LpltQebLqg7
         ZhinQnuxFp09pS8E/OAY98Zi0GnWogIern2i++kBXXt5+8LMNAbPV4O8xwn8pITzZP3S
         3L3Ys+2uVIZknxuLunWyd54rlWB3lPXOyJ4yPH9jNoApGM7e+T/fLW2OOA1qSbhU8nJm
         y2E/hvNs/FMrYuzYOBgY6cxr0g0LkeuO+TbqM0XvAmrRgfnck9fGWlCREov02c34nb3N
         /Q/LgBRrsyG+VPmJwHyIFhDFnoSz9TwnASOeSd1N4lXNk8XGvEbYSdyw3/Rx8XzWHzO4
         JSQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740585502; x=1741190302;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SyeASWI4oqcBy5VOAJBwwwM7P7aYnUdkASETzUwHuqg=;
        b=wOb3KZrGPknSqXDGHkXxl4lgPlwvPFerk6V/nll8RaJX6ORnhgKCv+U/3CFoypQq0X
         FaUqFVkt46Y+fcdyRJYV+xCjVPBQh4jEkVA1QiHcouzRMW4p4Trr030Myy+iDU4gyk6K
         FFtPBtNeFJY7HqDe3QVZ+C0C1PDH9TW3cvlXh3AgJARha7YSBaWO1JvyRTW3RuTF0lsI
         jWCj0QgpBsFvog7IRtS7VZmAwNEtyPGjWzFNR6lS8mL6p4AkLDZvmtJU3FFFRK0XBWO6
         S6KxiMo9WU6+wcWaMEVIeRLtm+E2J+WRq4vAjq44yWjZN+3hEo3m/+v8ZOnmQ9l7cvuq
         iJuw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU37Mo2rLBNC1fWAvhD5LooPCw8qW5y+uOkEgUNWSSELDmI/ffJl3WfEdeyBpSAnx9wiNMGhA==@lfdr.de
X-Gm-Message-State: AOJu0Yzjacia5QyMwWFzWACf2vrkWrRJC2bmeT4Ykxeq3ovAM7LVH+uJ
	NSdxA4S2+n0zLm9+i2zDhR0tSBU7rLC7b1JmCxsu4AwXLpNDaABH
X-Google-Smtp-Source: AGHT+IG9Oew7WfRRfEqccPwGlzZOtLa4gh5ZDpYjnrrg4733aLeGe1gSuIARFfloax/iT6oKlunmFg==
X-Received: by 2002:a5d:6d86:0:b0:38f:231a:635e with SMTP id ffacd0b85a97d-390d4f42f64mr3784202f8f.25.1740585501621;
        Wed, 26 Feb 2025 07:58:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG1IyH/Djy3ln5Sttbnw++H/HcMoQLkAWFt1rPZzqtTQg==
Received: by 2002:a05:6000:1787:b0:38f:2234:229c with SMTP id
 ffacd0b85a97d-390e13071acls5037f8f.1.-pod-prod-07-eu; Wed, 26 Feb 2025
 07:58:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWjDzxbR/VK/BRxt/d9oIZFTJcHUH/9z6Wj94oA2Py96liF2p1sW1sDryOcc3T/qLUC1mXXWHxJ784=@googlegroups.com
X-Received: by 2002:a05:6000:1563:b0:38f:2774:12fd with SMTP id ffacd0b85a97d-390d4f3cb6bmr2774545f8f.17.1740585498730;
        Wed, 26 Feb 2025 07:58:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740585498; cv=none;
        d=google.com; s=arc-20240605;
        b=awNE+wqHwRQ9p+mQ06leIaRtapU6FAQ3BpBMLuAh9JBkxPLSWuRa1bF4gSLOpdOYyS
         GRtt8GVPTv9XRWUU7OSkSBXVcs1GHIFTLycj8YyFWTL8fDU6vQTJjb2chp15mBAdoNOB
         sn+wEfFQw8ezIUf/dGsABAeTavuD8lABVeUFTyFeLG6oBv7+5hUzxV2KPn90fJ1Z3Wp+
         4c8T2Lnd10QP8T7KG0VcjbDFRmmKe/GQNKBqt6824fdQFGeNPfQOrqiDp8PiO+C0bE7H
         s2vgLHlEC7/Lc0No6g9kQle/Q+aSx2n7L06rE3Zu5XFYaWBwewPVNbGu2ttsHYD+JW+5
         yMag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=RITIVTCCbPTEmlznoBvDtT81aFPY1TF+qiJ3KGGJkqY=;
        fh=ixdtqmFayzRtiDKEAlb8ZMQ7uDWsa6W8i23SONEPr5U=;
        b=jWgZf64AEfaVugxH5P786RFXzjd9TCjjh9wSDH4KwUFFVMCsmCxJscn+5RqntQVC2X
         qm5VCdYd1uEyGVSrL4R8FR5gsh4tSr3bcNCPYD7ju+b6gYSqyETpONO/5gZyN0PlGDOn
         M7fcmJriBQRdrINcmX2H5uNOFgcY6+Ye1D1gmjha+zRNuCjLLNT2gaXfTuaj1Z+j0Zsa
         zjR+RqTmA5cuKyD5Y5bSWXPJJhkCbaFsqlbRt5F48iTWloS4z2jqF9rxBLqjShvyvYvA
         de9I8nYO0VEVCG6sm+qtE1xDGN1UWL1dHhl9Dl94HdoGbwqA8SyytSlSoUpEsoDq8MWp
         zkOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eYUovpnL;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43aba0d3e09si1509735e9.0.2025.02.26.07.58.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Feb 2025 07:58:18 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id 2adb3069b0e04-543e4bbcd86so7948383e87.1
        for <kasan-dev@googlegroups.com>; Wed, 26 Feb 2025 07:58:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXXla+xMlt5ZAU/GZE3KyEvPXXzVg+o6OxLLa05nKzyGMyi1MEp0nrTjUoLMt3nef95BLIIUMcWx18=@googlegroups.com
X-Gm-Gg: ASbGncuxEyk/s0dii4IvPIpIvBEZ6uQeTaLYjqhJAnMY7inHfaYzpEAIKuPC/dZ6Azk
	b82YXjcGkmNO+n+WBe3Ug+Q3rIrMkaad3kEqvIDIUW/plvJC1VwZ/1/QbvLAIDCY4JonJ9CV9ma
	vu1v67pSYcDU59g0ujnkbD2VxAA5IGKXwW6PtdeX3JT6JLGJBO1iQg2tv885O8qaAVWXjkVmRZB
	snYufPGlMENW5UKaLhoa5XjyhNlG9M/otnC9e0HSwr7Wz40SJ+bnj0g2qqm3ny1mxunbYHdpQIe
	ZUo10OQbKipuCGAWVgqd8ZIQ59IY3ZhwUKm4BaxizRpqUKSY
X-Received: by 2002:a05:6512:3e17:b0:545:5d:a5cd with SMTP id 2adb3069b0e04-5493c570908mr2649719e87.6.1740585497794;
        Wed, 26 Feb 2025 07:58:17 -0800 (PST)
Received: from pc636 (host-95-203-6-24.mobileonline.telia.com. [95.203.6.24])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-548514efaccsm491496e87.155.2025.02.26.07.58.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2025 07:58:17 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 26 Feb 2025 16:58:13 +0100
To: Keith Busch <kbusch@kernel.org>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	Keith Busch <keith.busch@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Zqiang <qiang.zhang1211@gmail.com>,
	Julia Lawall <Julia.Lawall@inria.fr>,
	Jakub Kicinski <kuba@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>, linux-nvme@lists.infradead.org,
	leitao@debian.org
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Message-ID: <Z786FcgpcjVZw4WI@pc636>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp>
 <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636>
 <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
 <Z73p2lRwKagaoUnP@kbusch-mbp>
 <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
 <Z74Av6tlSOqcfb-q@pc636>
 <Z74KHyGGMzkhx5f-@pc636>
 <Z784iRR13v6SkJv5@kbusch-mbp>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Z784iRR13v6SkJv5@kbusch-mbp>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eYUovpnL;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12f as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Feb 26, 2025 at 08:51:37AM -0700, Keith Busch wrote:
> On Tue, Feb 25, 2025 at 07:21:19PM +0100, Uladzislau Rezki wrote:
> > WQ_MEM_RECLAIM-patch fixes this for me:
> 
> This is successful with the new kuint test for me as well. I can't
> readily test this in production where I first learned of this issue (at
> least not in the near term), but for what it's worth, this looks like a
> good change to me.
> 
> Reviewed-by: Keith Busch <kbusch@kernel.org>
>  
Thank you for checking. I will apply this.

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z786FcgpcjVZw4WI%40pc636.
