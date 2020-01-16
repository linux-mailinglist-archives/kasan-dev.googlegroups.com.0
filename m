Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNXZQDYQKGQEMNB3REI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id C74F113D806
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 11:36:38 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id d21sf13571213edy.3
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 02:36:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579170998; cv=pass;
        d=google.com; s=arc-20160816;
        b=wJjt4K6EPco4FliJK+9Ge1gu0rgrSJ+MlKnrnYEas4ihRO5n5M0qLXqxGug9URXyIg
         BWRCCA/ArlBi6TmGuDyzhO6JswjBO4ByIYosPYIzXBzRTQ1CHLyRQ9VehIJnYbY/5Zs0
         S/P7alDGsck4/QUHoZKmuCCtMEkMmIkuBWZfbLxT8ByLn7y3dfHlP6z3OdBrAb+1wgUc
         CbxNpXtzO0MZW1XXv6pAjw6nZEFZx4bzAbFzxYZDd/MwAEdIYJ+wyRk6ENarnfh1Hcqi
         CMiSWQwNxtiNrcbcPrTIWOBYkchspopNt+/L3HeMJCZXA7sgdVbBYqIjU7//NIIb4+cV
         jDEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DkgkCVpn8UOKh5qvZbeKyzQDZ9fRqvkCfR1nOyXo4Jk=;
        b=eN+WVS/BB+IEoRygtruXfN9u1PYcabgK4g4z597HQdgn8h2z4l/pg15mMmnMiq8+dc
         gQ0T3AqCZ8GRsR0XPJ1Vwxc3BvOFEPPa3MM0wZHhWOfC4YLOaRgT8MG1Pj6Xg5iDBb1z
         IgDGRROKKznXe5rGhlX6EzzBLkrHagBhEwpDpAXTyCHv+fBvkW6jFundJohhve2+Emzf
         ksvmrZv8j0w6xKcpU5LQFMo8jHM8sAnqs98fF0g29MVfnO+Ml3mVsDtv49vWpXT/QKWJ
         R2Juk2cwBfgbf1aKfk3i2WHZ2JwJEAI47eAWsKikklJDLUq606MVUKP5ySrb5s5LMCb0
         Dacg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=myg5QbUS;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DkgkCVpn8UOKh5qvZbeKyzQDZ9fRqvkCfR1nOyXo4Jk=;
        b=EmnkeOaQUoMhtREQScVkvR6rHXgUnfANVx4z9om00M7Kmu6SihhrYqDNIS7yXh+LDB
         lS6/GjQjZzuKrxpW4RMHBR5hQd3I6xegD8g5BaYv1oLBQmszrRBrEovW1f490x2qbeXF
         OvW7e8dELwtJAFoT29kJlyVegLgrO1L1T/4r0AlenMrdWcaMB8Bl7Wvmj9tGPxPacaIn
         DF3EhELeIz8Hz2/QYxsQ/s/WdV3I8PPFcxKzo2HZ3gNV5cqUMOgJ/Cy5VpumabsIxbyj
         M1a22OsiK3CAzxacqy1fCDw/yBLgdx/LphSK1pI9OuCaFOzaK0AjhwxFX9ohqscVF7Qb
         b4AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DkgkCVpn8UOKh5qvZbeKyzQDZ9fRqvkCfR1nOyXo4Jk=;
        b=blLxOJrD53KqaO88mX0uv1ZzIx1xL0kvWjplEPTvGfryk9Bl3jSCt964hjNCO1aaxC
         7yRmtRdSJGtHY1UZbkCkzo0w8dbBC2X+pkWahjfZKZm72Roj01MVXGlALlTqFOIVVCNT
         JzffM1+Aph+rwcTqKH+P7j2pZiiDHiif+nmUFDaVm4NiLtNoP4y/sQIXSpqicqFG19g7
         tJ9Pj1l6zCGVt73/w+MFgmRik5P3YypJfJAfbb9OzqdQFLXP1PHpeGhsRU8jo6FVusKB
         9RvmStYE4znbWgpjVf4RPllTk20b2ghElFxUuGJUqqQwlnusFiirT6Z8L5xpFo8MjLLi
         /J2Q==
X-Gm-Message-State: APjAAAVwczklLAZQkpDiGMahJmTpvn6/g7Gn39c1tKVTeRZ6C+awKJkO
	e9U2GLFNe5h9O7mI+vAPbMM=
X-Google-Smtp-Source: APXvYqynVjD7b31OVHUycOcX3XT4MtZHWbZ0N/x0np4NiKTOIBp9U86WuKKTmnfdyB7LF3NmrL46bQ==
X-Received: by 2002:aa7:df89:: with SMTP id b9mr34445874edy.99.1579170998531;
        Thu, 16 Jan 2020 02:36:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:584f:: with SMTP id h15ls6116043ejs.9.gmail; Thu, 16
 Jan 2020 02:36:38 -0800 (PST)
X-Received: by 2002:a17:906:7c47:: with SMTP id g7mr2177570ejp.281.1579170998056;
        Thu, 16 Jan 2020 02:36:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579170998; cv=none;
        d=google.com; s=arc-20160816;
        b=w+XQ3AkRnRXvSnA0o9ybomegRUx+S1jTrnCHAyu5sM6o2i7Ldi/Tg82Ow5oK2M1+UG
         zs7FR+Ic0TnOKqmvcqlsGBu8kwdD26tUilq7tTJub42v8fDZadR0M6XkeqoewMfN4SRn
         oM2Sreg2Ygx2MxdDRxydYA11GHX9owDLe51YN1xx0QtBa8W852BTjpcHAwJfA//YHlXU
         wWBPg6Gu8BxOKMy/fcXx39I9ezD4U7Cf8KpIZ1ChKG7UUyH9vMm8EXKTJ1e3ZFeYinHp
         0XjknGjUhIdRx0K6ICBYNvUQePxL4adxBK1mbbGzrtSOKCWSb03FNxwLvkkwaDbWYlmr
         UbGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6eYsHx9cl8AC3I2Z/xAMb/OglACMn1Ya3+4GA6djOtI=;
        b=AhkotV1x97zI7TYFPiXFfIiLTbMGZQaZNRvpc1rjqgP/0YXdbS5ki8mYLpbhhP1epE
         FP5V/oNO9DS7pRHSu0OKpbPxH0p4nnIVDJalQk+ir93v+LHGKinpQaB7q8rMQigZQkFx
         BR3dbfxUA6BUlnJ8KayeIMCVzPlSLs1Bl9e/j9ZbeUCeUoeBBp+9gQsvyzXPOMa2IbmN
         DMRl6TtA1U7JhZSRCBRijrcA0RpmfJlDw7yZd49iJvI6U81PHxih0Q8BP7D7+Y0z88mg
         qlj7+4JKrcJkGKsWpbkpdDvAb3RX+nVAztHow6zGg4FzXo1oigC9IsZ4qwGb0a5Ab34b
         oeUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=myg5QbUS;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id n21si857894eja.0.2020.01.16.02.36.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 02:36:38 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id b19so3157098wmj.4
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 02:36:38 -0800 (PST)
X-Received: by 2002:a1c:4144:: with SMTP id o65mr5496764wma.81.1579170997525;
 Thu, 16 Jan 2020 02:36:37 -0800 (PST)
MIME-Version: 1.0
References: <20200115162512.70807-1-elver@google.com>
In-Reply-To: <20200115162512.70807-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 11:36:26 +0100
Message-ID: <CAG_fn=WgQtqhmJ4Nr8N9VKLWaJpZCdyPy5NPUdRpUBJLZSstaQ@mail.gmail.com>
Subject: Re: [PATCH -rcu v2] kcsan: Make KCSAN compatible with lockdep
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@redhat.com>, will@kernel.org, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=myg5QbUS;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::32b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> Reported-by: Qian Cai <cai@lca.pw>
> Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWgQtqhmJ4Nr8N9VKLWaJpZCdyPy5NPUdRpUBJLZSstaQ%40mail.gmail.com.
