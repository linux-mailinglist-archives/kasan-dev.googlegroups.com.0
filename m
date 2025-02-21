Return-Path: <kasan-dev+bncBCY5ZKN6ZAFRBKG64K6QMGQEMGQCKPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id C191FA3FC1E
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 17:51:54 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-38f31e96292sf1488950f8f.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 08:51:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740156714; cv=pass;
        d=google.com; s=arc-20240605;
        b=ABhTu1NK7JfKuf3dqFEUilYylXNyC+dxX6eZrmIzCye2CcVs1fgIX0woS0kteBQK7a
         Jm/x525BBFO65aEU4u54Gv3VY1pCjTMsJkr4AHvwEJ22MEltF+c03D953/tInfZR0tGa
         InQ0ETXuioYPYMFwwvfmUfHiL6U5Leo1WSUhgoCNs2O6saT7LMxes2dSbRpd67tgvDsq
         AzRhufCq1jTmKNGxwAkfJJGT8m/rU6UVswPLV76vmmoqXdyzO5GT6mquAD5Uv31dIpXk
         NKKkGd8rzy03fusmJTK1cYuIFmLQt6Nu5bcVgcOwAGrW2MYwRfrZhkf5+jeCCJ016LDF
         lRzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=13R+I7jXAmR/QDG3f12wn88MOcIJepm7djIjtYck8m4=;
        fh=ivX9B9ScBl+M30Txj7TtCTH6xYk3+mWnyy4d/5a//cw=;
        b=S8mAxJDPejnEkB616mZpiILIPYnIuvvrqD7CwkfV6kDxOnQu8+1d/dxxqoN59wpPIq
         xHPyXTsdtBeYH4ZOcZ9tZkrCe8eT4nBxPxOhOgrzdzrsWVgh43Y8DairEIF41VsUYMnX
         lX/e59DLPRqR8iRF1F9LaV9PVEDZgJ0HzzazKgxiNbjVbiP4OhF/z9cRKt36FvAbqzcQ
         YfU/WCpiwe6FBWLWMfSgtGVdzqhYf5XIwJza+7LL9gJcUtdcSL9Acvrn5zsipgY4N3BU
         Kcmm415zmt5iRYD5y2PWs0Z63VuEjGhb911MIjp6fvUg1ZiXFayz88HQAjjmceBLKD7H
         hKiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="e/Q5wch5";
       spf=pass (google.com: domain of mjguzik@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=mjguzik@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740156714; x=1740761514; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=13R+I7jXAmR/QDG3f12wn88MOcIJepm7djIjtYck8m4=;
        b=e4D5ijjzKimHEiIAJW4FfXyQS6aBXDE0q1rW55QBgYgPC+gYbBbqCP/vWot+junV01
         dZmqfDLCkBv8AB+nhjZ2XmkZTn1S5HWahRpsJZR9LOTbKnX07Rt40e4cVwYJ9E53C7RC
         97Ts+fkI+yDSvWNQBprycKxGOWwIDV8GI1pO4H0iC85DIOGc2sWMpgs81c3anRQr9FXM
         s3y/v5sEkJL7GJa+gNxfk878mX6a1XTgwW40LDL/2OBWRbz5AcWN3XQDNw5bfkceNdsq
         g13H/HftHA/oyjgMAd53CVHrZiglfhFgUNHagwoW1Sc7wmbFCmOQewTEm5MkNkXqPWM7
         vySg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740156714; x=1740761514; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=13R+I7jXAmR/QDG3f12wn88MOcIJepm7djIjtYck8m4=;
        b=GoujbggZPxVXhw6dnDoyLQ9K7RZpMusekdWvcJJb1ab0SrcqDa7zTpw4oaHpAd/NxW
         hlH6+Pt9g7AyeWWAy+y8YIU7psjT/uN2CUgsGwzQOTteem1FAmhj+S+t32TCt6L2RvrX
         m25YM9iabVV97mmfwfqgBdy4f3e8wCcO2k2IU1gR5nh2UTm6yYMpYZ8Bn4L6P9ltj1Jd
         weIi+HWcbvDrDeAKpwSu5EWplBrKk3c/RQOCzLReXQ3r/pDedeyGd8Lh34lz6GCMRj5q
         rX1lRfMNk64xohxxF/ooOmZb/lPBOlhTZfqtFbYeYvGrGEGkvQva8+kk48k7BtVfk6j0
         IhIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740156714; x=1740761514;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=13R+I7jXAmR/QDG3f12wn88MOcIJepm7djIjtYck8m4=;
        b=ronFu/iU+zTU8o/kg+U2OqCYwice7MWFFkStDO1rxn59rqCRdQvrYrAVj2e3U85Nuv
         cS8Sm6rFjjMwO/dzeJFXK/5QoHqsLloTTdctAnrcFfnYExPjuq5RHAFyK4v0tHz/kwk0
         QBHoch0vuEbtYNiYR8rxuyRSVfR0S+d+Cxg2wd4OU2SBUrbff9bFoQaemZkRvd0uqRWS
         /PcXvHE76F2CAsEPwSrEeaNcCcNhMEdCI/qWu7FBmGyy0+gZkKwRX+YQSuEYIIJ7PR65
         4afse+K/GK286uJ2/gQbVbuhqNzhM+g/Byffhj/243F/wewWPLfCi5vuTGWtozxMJqHc
         YD5g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVCM/fzeWyRTuJnUMPmL9AySS2zcycG98Dlpq1NfVrbl9FElc01LCnvhKEv3CKHK7uPHOCLgg==@lfdr.de
X-Gm-Message-State: AOJu0YwLPxgR0xh9yX0RIV8j/iAqxxT/nP5dHdnkAYJJEsMk9Olu+mXq
	ZauP8wxlTf77ouB9j3fMSWO+4+2Wqp+X7AQSolJAwIbksx4P1+eD
X-Google-Smtp-Source: AGHT+IECPhtOHnA/0/UNqNq1I3yR7hjbb64X83yP7/XWX9GvjLcjoJncNax86UN5Ls94db6hxY+nAQ==
X-Received: by 2002:a5d:64e6:0:b0:38d:e411:7dcc with SMTP id ffacd0b85a97d-38f6f0b06a7mr3312560f8f.37.1740156713322;
        Fri, 21 Feb 2025 08:51:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGaJJaBzbCiWppTdX6rxLYJcTl8nVAT0qj8o/sk/SIbvw==
Received: by 2002:a5d:6d8b:0:b0:38d:c0d2:1328 with SMTP id ffacd0b85a97d-38f61485917ls1535733f8f.1.-pod-prod-09-eu;
 Fri, 21 Feb 2025 08:51:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX21xG69KNVk5C35WEjiCM1ki29dzYutpTqWxbP/WWBy6dusEUKQ1lkRiXp82oVdI9R1jK6kG+6IXM=@googlegroups.com
X-Received: by 2002:a05:6000:1fa9:b0:38d:df05:4f5 with SMTP id ffacd0b85a97d-38f6f0aff40mr3939181f8f.42.1740156710959;
        Fri, 21 Feb 2025 08:51:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740156710; cv=none;
        d=google.com; s=arc-20240605;
        b=QAmnGwRhC4xqQUIwqlxFRRXKauzZoEA24b4z4XK1YDiMkZQhiuPxL1XU2vJ//V2+VK
         j8hkXiRy/Or0HhhCi5Cuj06k0bjZUgBp5FnuDVdD7GXogrzMdLRLGBaJEWw3yOIhV/mI
         VFNfbAQJmWpk8wRPHAIRG5KM3Rjx8vhDVDAyCC8ykPRRkKCz6U2MPt7i+DugWfwrQY4C
         hKRNh21G98oxkXxIITy93nwqVRUSasLfXlN3h8KXlJWMiFM7srPS87vSeSx5VD6u5hcA
         itv795ZanHJ62JBtnqAs8IAxvwrBiDeF+uKV7jx501sXXy2mvoYvgqA2988ank5hyVVE
         wFAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=L3GfVBZPNIG5qDKUks2BtPgtADXfzW3N1roYhgf4YM0=;
        fh=JRxLzovSORB2LFnkiJInO75KRpsHaOJhD5LAbJ+7fhg=;
        b=KkodbFMxPY3+vTKpoKB8IrqBLv3kdV43wMZhHXrPuQJKSmKsnwzBHw/Sh6PUccVaN+
         tFsWCzOhaTF6OyUK3IIljZ3n6/zdeNMlTxEoBUtzUaNqEFGQ+YVUCHHR47btXmqWzJel
         l90/8Jl4pBiBGd0rgVSRtEiuyeY/o014D/kUAxe99ZIHaNNd8cLudnoE31vkkR6IEVv6
         jLtInZFTlFRkN6vKSTCAR7waxS1fXA4zp1YeCIH42/EPEAoyp5QDl9BsvbNUXqrAYV2Q
         Bk33DwcC3qn2FUsldrUMODcfb6cBsSbHS2gjGbRVQzuEi5Z2QZvaLSH7fX0Ss24pPKRk
         8e6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="e/Q5wch5";
       spf=pass (google.com: domain of mjguzik@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=mjguzik@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4399c4dfc36si4997155e9.1.2025.02.21.08.51.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Feb 2025 08:51:50 -0800 (PST)
Received-SPF: pass (google.com: domain of mjguzik@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-5ded46f323fso3244748a12.1
        for <kasan-dev@googlegroups.com>; Fri, 21 Feb 2025 08:51:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVVvkWGeAsbu2XPrOICfkR4mDRfUdEk882zl7/IEOzDoy2c4BLue/Fo2VxWU053k/xNKGV+Cze66+w=@googlegroups.com
X-Gm-Gg: ASbGncuXwUg6YznlUA7q68y+AODirKozbhsDbtdYnFjkNRudWAceHkNJydT6fx3klkD
	ZXcPei3IpKW7VxYd90ew7EsDbszbWkrx4dFrAO9IZhAW31Y35fyLUaKgxADLv2hkRPQSj/HmbXt
	8Q4pM7gg==
X-Received: by 2002:a05:6402:5246:b0:5de:dc08:9cc5 with SMTP id
 4fb4d7f45d1cf-5e0b70ccd99mr3708605a12.7.1740156710272; Fri, 21 Feb 2025
 08:51:50 -0800 (PST)
MIME-Version: 1.0
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz> <Z7iqJtCjHKfo8Kho@kbusch-mbp>
In-Reply-To: <Z7iqJtCjHKfo8Kho@kbusch-mbp>
From: Mateusz Guzik <mjguzik@gmail.com>
Date: Fri, 21 Feb 2025 17:51:37 +0100
X-Gm-Features: AWEUYZnfVYIJxHkGF1zZWtSz2bHpYaGIafeC21mOa_0SYKWj9c3lZDabKwAoH5U
Message-ID: <CAGudoHGF8ULGPEE5E6ZCTcVnm3qjY0BfT2DmBjKohW_rDK0JSw@mail.gmail.com>
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from kmem_cache_destroy()
To: Keith Busch <kbusch@kernel.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Josh Triplett <josh@joshtriplett.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall <Julia.Lawall@inria.fr>, 
	Jakub Kicinski <kuba@kernel.org>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>, 
	linux-nvme@lists.infradead.org, leitao@debian.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mjguzik@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="e/Q5wch5";       spf=pass
 (google.com: domain of mjguzik@gmail.com designates 2a00:1450:4864:20::533 as
 permitted sender) smtp.mailfrom=mjguzik@gmail.com;       dmarc=pass (p=NONE
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

On Fri, Feb 21, 2025 at 5:30=E2=80=AFPM Keith Busch <kbusch@kernel.org> wro=
te:
> This patch appears to be triggering a new warning in certain conditions
> when tearing down an nvme namespace's block device. Stack trace is at
> the end.
>
> The warning indicates that this shouldn't be called from a
> WQ_MEM_RECLAIM workqueue. This workqueue is responsible for bringing up
> and tearing down block devices, so this is a memory reclaim use AIUI.
> I'm a bit confused why we can't tear down a disk from within a memory
> reclaim workqueue. Is the recommended solution to simply remove the WQ
> flag when creating the workqueue?
>

This ends up calling into bioset_exit -> bio_put_slab -> kmem_cache_destroy

Sizes of the bio- slabs are off the beaten path, so it may be they
make sense to exist.

With the assumption that caches should be there, this can instead
invoke kmem_cache_destroy from a queue where it is safe to do it. This
is not supposed to be a frequent operation.
--=20
Mateusz Guzik <mjguzik gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AGudoHGF8ULGPEE5E6ZCTcVnm3qjY0BfT2DmBjKohW_rDK0JSw%40mail.gmail.com.
