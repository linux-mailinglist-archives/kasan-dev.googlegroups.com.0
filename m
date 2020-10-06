Return-Path: <kasan-dev+bncBCZ3BP7LXQLBBRFI575QKGQENWRO7BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CCDE284409
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Oct 2020 04:19:49 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id e3sf1941669ljn.11
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Oct 2020 19:19:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601950789; cv=pass;
        d=google.com; s=arc-20160816;
        b=DTi+MlkDr3GGzsNBLcutCHTDpl/zv9dcT7TMZeuPiiq/Cu8l8U2wXckbj73m7vQnBH
         a0+EUrSMVvpv/rI29SapKWk3atMIOnqBzfEKKe0L1CNow3LO8K5afBkm03qNWvCpgdGJ
         j8px/g8eJt47G5LnBwxWMl0/MQ3hbSuWT58QE5VP1qa9qovRbr0d+Wb1/mGDRoopAqcB
         t8omFnujxZqDPYLJmredH9E4iIqcCNBh8CJBc+LGWVlaoXRnexklrwWFsnPeKE/iD9xq
         2/GPhk2W6Vgg/6Uyr1bqAjG1vDFmU7UaEZ9ykoe7u2Io/lWuLzonn3TZTLH5MvdrshmA
         j2Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=KOiBmuzjtafKBbzgMRL7tgzYKOuUGpMUAkuiUq7kEvo=;
        b=CbAke7iI0WLIT2bIWPXhxd3aDPu5/WrS5Mhe2Yo76PbEP15NsVCwstbTdCXt2/9yU5
         vclqwK+7GAJQ8WQfjwq0/cqVZDpMEas5dsqQP2lbn8lw/pbs9dv2vp+/GwB/JpLiCVef
         ZnovSQ0iIr7YgeHoZoFQ0+IZde64emCyG6eGKwWfElu1rqwuzv6r9GG7RNxijDSBFEp7
         cpIVGPPrm1YF+g4AOsVruK72bM6lAvJroR7DgTWENWQfH8gVH54YPNJQXkuvSF2KJkKi
         LuXQOAA6UPeRbBtbiY2Jn/oyRxh+XDSlWHrkySbeFBQNENd4/Gsn57qjK69oC5LVzXOj
         1oGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XhNVw1+T;
       spf=pass (google.com: domain of danielmicay@gmail.com designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=danielmicay@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KOiBmuzjtafKBbzgMRL7tgzYKOuUGpMUAkuiUq7kEvo=;
        b=r/5Mi9K7F7ZVUEUf2e8JtDPUhTV+MhTMFFbSqLWoe0ETMexq4cZ3jd8LUQXrxhKWhL
         P3x/97Ka6z08KJqzZ2qMJP2XrSg6u8q1ewbQhnRe+Us17udDoN7X+k5DgIk84VdIaBIV
         GP8m8seYn06P9YE0mok+tZn/+yxwRvBU2u/VEAy0R2TIdeJVeLLKH140+XLE88ZKAOjx
         iGMAWhAZJcgiytW8cbw7go3QrRb4vCsiicgyWz4EPNcyFnlkTXva/sLVnSiFeQkocF6z
         Kc5TTiiOM9I/eQbd35h6HdTQUGlG29sF0nb96E2pejgv0pyMQJ2Heg+hwE3039w3p5Fa
         tXyQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KOiBmuzjtafKBbzgMRL7tgzYKOuUGpMUAkuiUq7kEvo=;
        b=CiPpt5d/kPjjfsT7DDpQ9PziF+lUEzkYp0XdRIE/HIkQIAp4YKSlwiZBknXjLbnBJl
         doCk2MKVBZ0Dyb+1Byg5sMYlIPNYtasq1tgl6CMsGnEuN54xKao+jIiABeQz8xF98usX
         rQOlkQVLBgnyOJHUxjRo8Vt/RotwAu6O0YjNNCVF0AG57bPY+yiXSq3j5ebkSPWv/xBn
         /mclk0UBO4wYJmMhHF+KoDJEinxDV+KFBA987P6TN6HYJtdP4ev8YSPpCzUi25ATHVHE
         onMKBDdrk5rxbxbXp5LQZRcpTdhgQjKD0i3+FAR3S40kB9SPDdCch9dX0/HFxEOu9Dg0
         ENNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KOiBmuzjtafKBbzgMRL7tgzYKOuUGpMUAkuiUq7kEvo=;
        b=gOEO+McFkG5JEl01Ae3vy6YuVtrL0yOfRb43qgX3fQShpLxznHzbKCywq5dV7h/N89
         QoYF9UACIuhj5/hgCVsJfbvHMjfwfPSHDTvwhRrcmcc6P8rIyx9Ely7oHCuVTuggoT+2
         k8hFiYad9uv0gVzp7R2JQTLcjwz/EB/HI5gbpOk2BWAjuWXB0rpWU7WEYeBvBcCSWiLu
         wHDW8S8onCMbXmsmFWFHBj9b00JVgMqJCVX9GgWDGYsKJXw6HBISvlVEk2zx37UAtwbB
         mQBdwvqx4hFJWjxXH/sSI6+/+QlmTWegy+rz4SRmT1s7GDjULd0Yk1YvDKuhUjqPE+ph
         it/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53183l5Spf3827NpNCMK6p+M8k/jv2cZA8TihdraXtnF1jMaw+vT
	/tXaH0AkzNlc6+Dx3bBRlNo=
X-Google-Smtp-Source: ABdhPJx7HQwtlt+5jeaLsbU1dh8/XQOssNiAQ1i75NIstLJF367ZP8jRBDd69XrkddPmkFrQ81Rndg==
X-Received: by 2002:a2e:9f49:: with SMTP id v9mr875677ljk.369.1601950788893;
        Mon, 05 Oct 2020 19:19:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls1177496lfd.3.gmail; Mon, 05
 Oct 2020 19:19:47 -0700 (PDT)
X-Received: by 2002:ac2:43d5:: with SMTP id u21mr754842lfl.135.1601950787889;
        Mon, 05 Oct 2020 19:19:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601950787; cv=none;
        d=google.com; s=arc-20160816;
        b=Z3prete7ACJQP4xhnoWtGB+G0l5zB1HBkO8g5rLj6nOXlla01YpSpNfvshNcAxIMiO
         PkH6FSnnsUN9uR1mNv5CBl4F9OI/qsOFLBlOqAj1s1YzjXq0e1LMuJ/rKI1rccv6gMp6
         6PKYtcqWmnEHU7EWzXKWSzGv+ZFSJGgA5A72Tg+3yuyxUnZAetC/mVmunB9LLD6UmtyA
         9JzzousEIBQMQD5UuXv4RZP0dKjnUbTs/1FLTxxsDYAkQ6gPzHLNoRSU0j2TX3Bq9DEL
         FfjvhwrwfqgXQXpyK0t2og/KUFLYFrJZNra7ENqcaKxQiMuYk/ey1+Ujm3OSrBvgWbQf
         9+9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5RQGQQnzUDnv0mOraeBJTeR9VvHirvaV4JaPm4c+FnM=;
        b=w5941uQ8RjTzXxAD2qIbOPu+1snQn4RLiUuGkXYiKuTiuS6r0O1gPPDNSpY6Mmf+zJ
         /104bimcHKm86RIZRJOdYBHkEnm1FX3PPK1oCceKvNPr4iwScNbzfI+95960ZPYIGY9e
         sZz6xfgFUg5wBniyMT557Yzjh2KkdbUifRzW/EcTrWLCvzq6FZI1qlA8duUMKt1+89ew
         cyDD/HyczPMjBi73dviWopBR4vFGJYa77ZYcJrSq5qanRU24uNHqviFLwulRd395aHR7
         xJ4hOtyNXIhIYiWTB96s/C4TNBQSls51aH/MxXMaune/l+XlykKV5OVMJYzUa2GMER5i
         UC9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XhNVw1+T;
       spf=pass (google.com: domain of danielmicay@gmail.com designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=danielmicay@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x641.google.com (mail-ej1-x641.google.com. [2a00:1450:4864:20::641])
        by gmr-mx.google.com with ESMTPS id y12si49605ljc.1.2020.10.05.19.19.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Oct 2020 19:19:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of danielmicay@gmail.com designates 2a00:1450:4864:20::641 as permitted sender) client-ip=2a00:1450:4864:20::641;
Received: by mail-ej1-x641.google.com with SMTP id ce10so15210799ejc.5
        for <kasan-dev@googlegroups.com>; Mon, 05 Oct 2020 19:19:47 -0700 (PDT)
X-Received: by 2002:a17:906:7d52:: with SMTP id l18mr2771101ejp.220.1601950787443;
 Mon, 05 Oct 2020 19:19:47 -0700 (PDT)
MIME-Version: 1.0
References: <20200929183513.380760-1-alex.popov@linux.com> <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com>
 <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com>
 <20201006004414.GP20115@casper.infradead.org> <202010051905.62D79560@keescook>
In-Reply-To: <202010051905.62D79560@keescook>
From: Daniel Micay <danielmicay@gmail.com>
Date: Mon, 5 Oct 2020 22:19:10 -0400
Message-ID: <CA+DvKQ+-k9pk1mUrEiTRKzSsz1ugCiv1A3Owd97dop0HPXa6MA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting use-after-free
To: Kees Cook <keescook@chromium.org>
Cc: Matthew Wilcox <willy@infradead.org>, Jann Horn <jannh@google.com>, 
	Alexander Popov <alex.popov@linux.com>, Will Deacon <will@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Peter Zijlstra <peterz@infradead.org>, Krzysztof Kozlowski <krzk@kernel.org>, 
	Patrick Bellasi <patrick.bellasi@arm.com>, David Howells <dhowells@redhat.com>, 
	Eric Biederman <ebiederm@xmission.com>, Johannes Weiner <hannes@cmpxchg.org>, 
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Pavel Machek <pavel@denx.de>, Valentin Schneider <valentin.schneider@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	Kernel Hardening <kernel-hardening@lists.openwall.com>, 
	kernel list <linux-kernel@vger.kernel.org>, notify@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: danielmicay@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=XhNVw1+T;       spf=pass
 (google.com: domain of danielmicay@gmail.com designates 2a00:1450:4864:20::641
 as permitted sender) smtp.mailfrom=danielmicay@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

It will reuse the memory for other things when the whole slab is freed
though. Not really realistic to change that without it being backed by
virtual memory along with higher-level management of regions to avoid
intense fragmentation and metadata waste. It would depend a lot on
having much finer-grained slab caches, otherwise it's not going to be
much of an alternative to a quarantine feature. Even then, a
quarantine feature is still useful, but is less suitable for a
mainstream feature due to performance cost. Even a small quarantine
has a fairly high performance cost.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BDvKQ%2B-k9pk1mUrEiTRKzSsz1ugCiv1A3Owd97dop0HPXa6MA%40mail.gmail.com.
