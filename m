Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNXC4P5AKGQE3ZWH4VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D21A263043
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Sep 2020 17:13:59 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id bo17sf1557764qvb.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Sep 2020 08:13:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599664438; cv=pass;
        d=google.com; s=arc-20160816;
        b=WeyC7W429upvmR8305g9Tb4XxJtF9FF3nAM4I0igKmf72wwqeMtPIUJPcGzrprs0JR
         Pox7l9Q7Qb9Rkbi7I/YEBW9j74og/HBL7OftaTDvhKj//IpXzVfRIwd86jTyCb1I8uUf
         UEfL6dyqaBZ5K3LyR/tzcxFMpffG/LoJTzD1HZO+2UrOei0EmHewjKDC/5oIvisku1Z7
         +TA2rpBI/p4eKgsd1rniNrjPlCX2vjG/RJ6crSUukVFcUwwkR2b9oES/dUfgZ26T37XG
         wBjqAX51w5Dl890sW9w4IOaKImruiYeFWuSLAvledz52Hl/li4/OcuENnwV6W5mj1H8G
         S4RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WUMD63I53/PclrK1+T6Bk+wljmghfe+7HgfqGa8XyPs=;
        b=tSgl7i9hPJXFZ4ovgVczFGmm8jIgBeCzyyIify470M3z+ZNWQ2e+F5gZ4mH8pnC0Qi
         XKDJA28acAhzqoqUSVDzvqTPAo1wFBXPcuWmK6K10B6EQM57ixlOpjT6Gymo5QnG4rqY
         rdTGZsNumGBhon5xiB7GmX8LnG/2boQWwLVNche4Cs0xE4phWxEy16L3A/H0dtU/Kwp8
         HVII6CJ3yHO11WRie8vTpjAEs+tEWHa1yarJKFXbEtfx/EJZlf+O8+zsBsQtb4wUkZ8K
         kBbrTsBEioetYXe4WI0lKrj+Z1bc7lZaRIJ0Qt7I/OYy6kU9KPdyys0ALdimH/k2MdFb
         dTAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OL93yWh7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WUMD63I53/PclrK1+T6Bk+wljmghfe+7HgfqGa8XyPs=;
        b=ILpaLEK6nhj5eC5KP/XoNcpz0AseWTXf2ApG0KL/vhH31rYsKdO47mw0VRsUOJrIRM
         v8FfYIp7MUT2PoXdVLUs+HmYdruJryFAhwspAG+4yK8mBszjpaSzUL2+5zH0oGOwdH4R
         DkII7GYHyZT+nMkTW86uaYkGl/OuP5SwPC1Y/WMR/CoR5GAD/bpJV4hCpOELStcL8AfB
         z+NFOUm/wmXJx4xBLrd78TY/dwD0I7s9fBvvb3ZTusCuwuUwMWegguyXk8zfIh7pkKzE
         s4jZxY1lKphsEFga77SAwdTl70UZcEYlOR5o4cSotVdOb8d0nlkUDdlo+LpECbT9njtq
         7ghA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WUMD63I53/PclrK1+T6Bk+wljmghfe+7HgfqGa8XyPs=;
        b=qBfalSGDNWqUK7ZqbStN7qlRrwFj4136gSUAW+gLgKuJ6F6IiD91gLP3qbwbVQZUnv
         97fMzJa4B73XeI3nJQsgRNJN7kxgQXF2L3hy/kGelBisUpT9nPuIxbFy9YotCrvItO2N
         9B4Pj5/paqaL6Zvi4UOSl2JVWpjSBjVEfU3PlxFCL8m37bqfbyoHeyLCxdc/6exFonhH
         TJmFGUehkuYtGRFTErq4upizMQqGGDphAsH4GSfHokGkUD04OPOy5CZ4BBpeX3Rxnlqi
         6XA49lcJ872IHQAGGugRfl2IGZ8WarWrwp9hsQuhbyB8xH6uFtkMnsh6jL8Of+pLzUgl
         24pA==
X-Gm-Message-State: AOAM533mpwjKn2P/3zhoTljcIdRBPpG2GmBt2byb/lEwNRAyIfbfADbx
	S8OhLFoqO9neZYKOoArf7Qg=
X-Google-Smtp-Source: ABdhPJwKgH53/tHfGXskv6AHX7gA+ph0BuOt4olE0GORXOW0BzKcJZlG+06gGKJ/qM6lXR4wWoZ2xA==
X-Received: by 2002:ad4:59d0:: with SMTP id el16mr4682527qvb.116.1599664438611;
        Wed, 09 Sep 2020 08:13:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9a09:: with SMTP id c9ls1472812qke.3.gmail; Wed, 09 Sep
 2020 08:13:58 -0700 (PDT)
X-Received: by 2002:ae9:e602:: with SMTP id z2mr3736975qkf.259.1599664437941;
        Wed, 09 Sep 2020 08:13:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599664437; cv=none;
        d=google.com; s=arc-20160816;
        b=WQkPOYFenlNWG+camlJTJWY8gRfTyHHuP5p7fWwIEMasPJeJzK8hBjMB0Ma1nELQf5
         1lKAoIjbj3kxrSx8UHlpK2QFY4ip9mg60s5ZegyC+7ij0J3buPGy5NJ0Uy0WSACN+4tr
         Rgudy0YCrcECQqqhuqW0S4LIt6sDZssQ5A2O5NybDjFadkdOgYSqyZUkPUa5zskHascO
         k90VZ0zVOZh4SUt4vnBsM3hVoOQ80uk6HpTtgmSv5jvI4k6d8iiupRFs0vwN+ucuWrCz
         P17U2W+6ZCKZZ0gBCxGcyZpFnkrf0H4tprZTIQTGlkgu+7SkUaVjOfdAp/0hHEWuEMeb
         e9Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=krZf25HoLYNOs+89jtLjxVuIVVFDL/DS0/iONN95wCA=;
        b=CEPRIqbmuQU/0B4p1yHTyu76aZ38zT5BKwtrZUlwWbzxW8BI2YjP5rSZf7s4AcwoZS
         qzTzToV9+/vtup6VQoupxeNQZ9lSdL91e/DCsYI4ejOembuHdsGsyeqUz77IZZ2i2qEu
         ZMk1e9dDn7WRVRUYMO1nPUNdjxzvn8qiPOmT13MdlM9R+/lmBJtVE59SNTCX/np8x5mW
         PXDVJmM6RRpC8IYZvcY90aZVOjVidJBX84IAeTiUWewW1ZNMfzgUlofmWj8DtsSWXdvB
         ECq40KsfvtMBBugrEM0/xnIjcaSbTmS7pjomqo3+MPYijmGPPvduMmGdwFRPDzbz14lT
         zo6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OL93yWh7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id a2si163861qkl.4.2020.09.09.08.13.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Sep 2020 08:13:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id n2so2724743oij.1
        for <kasan-dev@googlegroups.com>; Wed, 09 Sep 2020 08:13:57 -0700 (PDT)
X-Received: by 2002:aca:5158:: with SMTP id f85mr992820oib.121.1599664437260;
 Wed, 09 Sep 2020 08:13:57 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-4-elver@google.com>
In-Reply-To: <20200907134055.2878499-4-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Sep 2020 17:13:45 +0200
Message-ID: <CANpmjNMRMkFxdGHuyyWEPhMiW-uF4qjiKKRRrd_s13X2P6cv9Q@mail.gmail.com>
Subject: Re: [PATCH RFC 03/10] arm64, kfence: enable KFENCE for ARM64
To: Catalin Marinas <catalin.marinas@arm.com>, Mark Rutland <mark.rutland@arm.com>, 
	Will Deacon <will@kernel.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Cc: Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	Andrew Morton <akpm@linux-foundation.org>, David Rientjes <rientjes@google.com>, 
	Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Kees Cook <keescook@chromium.org>, Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, 
	Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OL93yWh7;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Hello arm64 maintainers,

On Mon, 7 Sep 2020 at 15:41, Marco Elver <elver@google.com> wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the arm64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>. Currently, the arm64 version does
> not yet use a statically allocated memory pool, at the cost of a pointer
> load for each is_kfence_address().

> For ARM64, we would like to solicit feedback on what the best option is
> to obtain a constant address for __kfence_pool. One option is to declare
> a memory range in the memory layout to be dedicated to KFENCE (like is
> done for KASAN), however, it is unclear if this is the best available
> option. We would like to avoid touching the memory layout.

We can't yet tell what the best option for this might be. So, any
suggestions on how to go about switching to a static pool would be
much appreciated.

Many thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMRMkFxdGHuyyWEPhMiW-uF4qjiKKRRrd_s13X2P6cv9Q%40mail.gmail.com.
