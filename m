Return-Path: <kasan-dev+bncBDK7LR5URMGRB3XT7S6QMGQE2SLU5RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EB96A465BA
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 16:57:36 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-43943bd1409sf47619335e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 07:57:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740585456; cv=pass;
        d=google.com; s=arc-20240605;
        b=ArjS1wHjnoLZZN7Z48RPYbfxxz5ITRHTQGSX500VkB5n0AKfN0PjdqQhnP4YkghDP6
         gzQmUDOv7l1XTpua1XRCOucYDj8rX5JrimFIuVffmS+gJ0aBqXkV3PpQMLV6OdqiVtpl
         86EdZnosAYLZJZGdzNPe4qWqAYyYQDhFHUluGM7Sxzo1zTQLwee1S/cLW3uabZQmlWcf
         fc15bt428dVCOhBLxOqPKK1bZQpKt+BQzb18Eu8rZtxQ1xIrrcR0bGdH0cct6kh8VeO+
         Y2zalCwviF1DLun0o4wiziA0qdFC20G6wkYHjfxSL6kGiNzl1hVlln4eFh8tRKOCni5p
         qwFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=kqzpyrdJTrsaacLmqL2sMERd1AozDW5NzLr6DG6/crE=;
        fh=p5BrWvoQd6z5gdKFO1wICyeT6blB8rVatFv0Rut+6uo=;
        b=PjtPwAg3c1dF+Grh398g/xE+acHh9UnK2rqHH23avWLOqoIzot8PQoypwHSdraykMw
         Op5XolO2LbNPmJwfC9lWo6DpoOXahFhsYUnnERH7DgKBejdy/Uui3outK6syY6QQcIkm
         WYBuCWCDekhFpCeSOn0lhhwzgVj7DoWgIMEI/WepACrRomxk0eCfInq4rBDyait58v/4
         19JOo7J7UMYuichqmb+zT4D9C2y4uxH02X0hKwKKeXQ+Mr9LA2YKf2cFPGcC1ydp/ZFu
         EUVNbrTFX74qIWJTk1bLkWn+JiUJx+URf0aP9nD9JH44J8usrg46+JpCQfAAdCDPW/Gg
         EvFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QHcyo14G;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740585456; x=1741190256; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kqzpyrdJTrsaacLmqL2sMERd1AozDW5NzLr6DG6/crE=;
        b=MexBlxTHXVCaKu9zaSPIZtvzIZL83ZOmBFR0XF4Gg+fZpjAO/1Uh51OyeU5YFvmKcQ
         VFhGHH2hu/ksv0JpFkoZfmQGXj+kKuYocBNUZdEqh9GMR7LRoNWqj+pVJbSDTE2btJn6
         D0ruS0xM+b+P9YgngunNCMu5hDDuNRG7GsG+59Tt73jKAdzKe0vNCbCXzqCKKTStnJTk
         HrdkEPLQQ/b/NA3sLbM5m/DJiNjvwVUIGqCA8RlrXBRhCf20VbO1b2Dx4+zWIPrOSSSb
         tB/LtpY84UcUd2NyFv4c4LA6pqDOp/7ZsbhW00mzRPuHVEEWywhuzLZHvlMOcCjKUrHz
         56Yg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740585456; x=1741190256; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=kqzpyrdJTrsaacLmqL2sMERd1AozDW5NzLr6DG6/crE=;
        b=LrAIk9drasyXYzIpKbkyuAg5lU+bmkOL6kgdUZ9yFDGJdJZ1s2aKasJeZ+OPiHcY0v
         7gqieeblHQw+Mn4+VGI08Wk2LLHfmC276rklDbHawYRg4waxdSMEzW/Vz/MtQ3CoFoVl
         hhyIADW+/RtYJkrNzlLXjDRVbRjRd2D14gMYHqZy2waqXT8IQMROrxHqqDKbnoYPpKsq
         PGing/hiqTcysSsu/OqQF8rSqLyRmSiarE/OyS9GK2Kd/7Bp4P2eNN/0relmKql3hws7
         u4nnd/cAII74WA0fL6GvPHA24JKPTm8k9KUKpC2+r0zixYhgYXxGjb6lI7Gmf1UfMvei
         GJTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740585456; x=1741190256;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kqzpyrdJTrsaacLmqL2sMERd1AozDW5NzLr6DG6/crE=;
        b=FTQ2lksc5u3dc1w+agtwl8qMrjLFdOmbCCi2JcnZxoh3O1Z2O3sOVp8t+RSvK3hLVV
         qjlspxdcO7opXTsHhyQSfe/3cH6Tjxs8CnwhiY8X4uyTDiIQ7mHrx1QSnQ5Xnxy/JDG+
         T7JSryazcMipawFRNnvYST+L/FrdNyJGkeTEMTO+uFl4e4AcbqzeAHpMpPdW6sBoUbVQ
         oXdFId9rstvqCG4QfQsvZQ/3Dh+icumCVL0u2sFU6JjHEN79rJhVpc00PbNt8E8UZnMR
         2MiF2SXBSrS6H01PHb1iCnk9Lj+Q5TmaG1CwXoxKMsUX3UwxvwsWGCny73qZ01mQFq1N
         nX0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWSOKI0bzrhmnjbGOZe/YYwQqIulsNihuS2VDB6I7fVroz8MsZwsgZHc1vo5GHtLDiDsz8eNw==@lfdr.de
X-Gm-Message-State: AOJu0YwLYke/7pPwKxyRlo6yu6jM6X1VrKKews6B1hdah00zMGoY3eSS
	18zdNb8f6uPuum50ggdX8btUrGSJoWotU92Ox/4DsKsYENa+cc1W
X-Google-Smtp-Source: AGHT+IHC5Ay2UwyJQrdRYpYlzOVIcfANrTzh7AGV1Dt7MOVNBr5D5oihOsAzjZsrD3AEY1g/is3vqg==
X-Received: by 2002:a05:600c:3148:b0:43a:b0ac:b10c with SMTP id 5b1f17b1804b1-43ab9027824mr29667185e9.26.1740585455365;
        Wed, 26 Feb 2025 07:57:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE44qK1Gn3/ju/nW7uAisoEUST9eXWMka0Vo7gRBPEUxg==
Received: by 2002:a05:600c:3aca:b0:439:9744:686d with SMTP id
 5b1f17b1804b1-43ab93f6cc9ls1480515e9.0.-pod-prod-09-eu; Wed, 26 Feb 2025
 07:57:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXMHO+YXOBWuTBkYYMpZ5jjojuBQTAG6ZdOo5N1ZRw/2054UaB3ncrMWn7uHMx/gast3SjoWnwC19Y=@googlegroups.com
X-Received: by 2002:a05:600c:1c8c:b0:439:6ab6:5d45 with SMTP id 5b1f17b1804b1-43ab902b2b8mr32866655e9.28.1740585452870;
        Wed, 26 Feb 2025 07:57:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740585452; cv=none;
        d=google.com; s=arc-20240605;
        b=cAahID7V8AW6pbOg5xTRl1OzCQGLpqGUm+x+s1F3Afpsdg47FDtsI4fjn1wAsZhjMW
         TekO1SKYzNNP/GSp5tR8RVf+NqPXzn4kJ9nZut7dzSxvGWpsTps6yvJuMGI2aHJiKxmj
         vDZLkoa8XsCGJ4V7tg6iFw/SNDONNSkhHaD2DOrsXZ9k8JMyPNrYHTUDrhiwnX4Kx+f6
         TfIjR/ulm89wyZBoxAeiR2IFZjPjimMQf4Z+DQ+3Cxiqjj51JKY67HLOQN7Wx5cBiqmE
         0BfIukbun4pyxyFDc924l+7nBqPpe3fVSbC8Z2/IVtElMOoAKeh9Jlq+ndqXOMPTQLrY
         9O/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=rkkyrTS/XUUgRrCusn5lCJsjmBp1WxMfD+vrhmxbdwM=;
        fh=iL4xpQSJ66JVaMNFxi34Q+Q8xEiS2JWSe69LKj+3Zig=;
        b=AFJpHPUQP0yEcAkVKG7hDwqsSBgyQR+kJTxasXdRi8Gvq4M521I8BQnon1vJAALYbx
         eK1DvYqeZJgW4MSA5fxUNyIdQVCDorDKDny1eqagquXfn4ttjiqLjqZ+MXsw3r0FKBRl
         cQb25tjDH+8jzFpasmHIw9D3QvBZL24YrvwyTph/fzdL9e0LN/yzawQmdxz6+QlvNFmi
         th/RYAaL8iECAdAtDdcJiWIbZWWP7JI+M/wxpcHsNBrL+KBMb12go8DGagK4VTqTsIGO
         1ZbUEzYSKfEYmR62Dh7TjZE7kh0sd1NO6jpQGsZwYk6Gn/aSD09nrmbmwlvQrmWr4Kn7
         Sdhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QHcyo14G;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390cd8e3103si162453f8f.5.2025.02.26.07.57.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Feb 2025 07:57:32 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id 38308e7fff4ca-307325f2436so70126261fa.0
        for <kasan-dev@googlegroups.com>; Wed, 26 Feb 2025 07:57:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWWg3WtOVOLemYlWlywcpBERx8oyXVUEM7+Sow1ztXgMyCb/A/NxjHeoGE/QYJGyX7n4D16tavTJJM=@googlegroups.com
X-Gm-Gg: ASbGnctQT13ldKehRJcj8dz/bW05ae1j0miFDldC+tROgfLVH7LWc1YOSILNSJvv14j
	WFrs/oEvzKxu1IgBwZyNZIc5/W7OyC79unhIw/4Exd6xk433C7656XqdUQH75WEPIc8RKqlCbW6
	+Pkaf+fjmqZ5kEEaBQwdZzKlK5KpdWwkuogHn3wFkflMoQfM+iX/3pr5XYkS7srD1PFAAbu94NC
	cMLLas88R68AyayrGfmfN/tnz9O3pXFNjjVlP0Dc0romGUS9cq7DybTqU56H/yN0pT/mOLRIIoP
	9X+xfjTsuS0w8y9wDVXoHW+a+BIDHq5hFN5/utPi9evUBdz7
X-Received: by 2002:a2e:9789:0:b0:308:e8d3:756d with SMTP id 38308e7fff4ca-30b7918bf8fmr31534101fa.19.1740585451801;
        Wed, 26 Feb 2025 07:57:31 -0800 (PST)
Received: from pc636 (host-95-203-6-24.mobileonline.telia.com. [95.203.6.24])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-30a819f4cffsm5537121fa.58.2025.02.26.07.57.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2025 07:57:30 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 26 Feb 2025 16:57:27 +0100
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	Keith Busch <keith.busch@gmail.com>,
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
Message-ID: <Z7855_cJh493vHNy@pc636>
References: <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
 <Z73p2lRwKagaoUnP@kbusch-mbp>
 <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
 <Z74Av6tlSOqcfb-q@pc636>
 <Z74KHyGGMzkhx5f-@pc636>
 <8d7aabb2-2836-4c09-9fc7-8bde271e7f23@suse.cz>
 <Z78lpfLFvNxjoTNf@pc636>
 <93f03922-3d3a-4204-89c1-90ea4e1fc217@suse.cz>
 <Z782eoh-d48KXhTn@pc636>
 <8899bfa5-bd8b-4d34-a149-40f30d12cb1e@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8899bfa5-bd8b-4d34-a149-40f30d12cb1e@suse.cz>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QHcyo14G;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22c as
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

On Wed, Feb 26, 2025 at 04:46:38PM +0100, Vlastimil Babka wrote:
> On 2/26/25 4:42 PM, Uladzislau Rezki wrote:
> > On Wed, Feb 26, 2025 at 03:36:39PM +0100, Vlastimil Babka wrote:
> >> On 2/26/25 3:31 PM, Uladzislau Rezki wrote:
> >>> On Wed, Feb 26, 2025 at 11:59:53AM +0100, Vlastimil Babka wrote:
> >>>> On 2/25/25 7:21 PM, Uladzislau Rezki wrote:
> >>>>>>
> >>>>> WQ_MEM_RECLAIM-patch fixes this for me:
> >>>>
> >>>> Sounds good, can you send a formal patch then?
> >>>>
> >>> Do you mean both? Test case and fix? I can :)
> >>
> >> Sure, but only the fix is for stable. Thanks!
> >>
> > It is taken by Gregg if there is a Fixes tag in the commit.
> > What do you mean: the fix is for stable? The current Linus
> > tree is not suffering from this?
> 
> I just meant the fix should be a Cc: stable, and the testcase not.
> mm/ has an exception from "anything with Fixes: can be taken to stable"
> 
Got it.

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z7855_cJh493vHNy%40pc636.
