Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSW27XYAKGQEEWM7LVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CBCC13CD73
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 20:51:39 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id x16sf510065pjq.7
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 11:51:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579117898; cv=pass;
        d=google.com; s=arc-20160816;
        b=OcXZTlCEZfzrYT+IZHyAR0taxsmf1vdp6qCUdKHyS5E6dkO67b6IPYCfzP57nhAsnT
         0bS/1XSADkBsUghLGRQ2yGo2JQ0XLpXaPQpFaccE4gy1LVwAoYNZ5qo2o0zZneMTJ72a
         bYakrpEc1/woP+qyiFcqZSJOh8+WRD0hNrefMR2lSQtWs1c/JpJF+xEm2Btx1r9ra5w3
         mBS74qMlp8h1Zx3nqUWqgUJPrxcPDRY2ASsUXt5/kWivk2RvVfkskf5OuJkB8PFCUtLA
         VBif54k2vsEQYGnt6AfkyNqsT/Fr3jHTrPb1kLP9JHRk/wqi2R11Wpxxxackw3sfcg4L
         1D4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Tjbbl6CXwwVS62xM+cDPkZHp243hpD9s4JtBNN57lTs=;
        b=pkcmQ0hfFXCn+E2KgGQjmXVCqUpLxLWB+YHL8wkgxWBKJApV8KadcesL3C2lCHIOY0
         FgWyCvmdjpZry3xG3hNHV1dH1ih+OjvbLfBJ36N8kDFXwAjqn05apr2hGi/8cN/QlVXQ
         KZ1zLIWL8Cn5E8L3ZsLX6UuhZZ3pqH4b7vfkhcg2CzsZcwQ/2FkN4jZOkCQrywNLHRNA
         o7K65MsUGNYNUSX5TThqTdDXD2l550BpQbmtGmSI7Y/vSd1DxQZIBuDnIlJiNwAL33br
         zUCDCJBQQUu1G72cdhD/VQG5YqviPpZUVdhXW/wk70LpZ9HETvSehCsQYQp7mdnctJje
         8rnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QeMscKv8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tjbbl6CXwwVS62xM+cDPkZHp243hpD9s4JtBNN57lTs=;
        b=rHRTq9StcWmsWs+44HmR1oGZac6limSy1eP1LU0+r6sk9mmssit5ih52UF/VhBKOxi
         eCgNQY2wTfYUmHLbgByR/+efWPuLPFobPy/+JKArrngmj8ChmcYXE+lnhmWr5MMs4QL4
         KNRRnGZX7Kxx4tVzl0ZOA4Qn6i0ZI6mtNwPT6ZRblHfyAQZ6TKIwJuEAHE39ZaDNvpDw
         nHdS/vZnDFXbZeLganeRz1GdsWVH7VBRSz9k9trOU0GIO9+OPgtvSI6J1iJRuifm4Yqf
         baGq/Leb9LCfCTcUK9dFolX8eV/YwMUEKaFzLj1RFs+bMY5h2r9Cn0ObVDGlpBHfxnlA
         Kd0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tjbbl6CXwwVS62xM+cDPkZHp243hpD9s4JtBNN57lTs=;
        b=jDctzzNasKTnnMtc6NCKU4eMNd5iewfm4qWYVxJRnpfHgFCt2jCa4UUM3dEdjuVZ6h
         4/e5xDrrGXu2w5yYUZ8neiFzdOZIB2WjEASGNDHXe8O2I9e2tf8gV+XB+bfN+z98/p4T
         4BX0FhkwR/Wl5i3PRpuiHeI5jLzYMK10EeNXIAlpX/PPGgNs8AiE2E1LJ7HDccJR1d2E
         FSYGDFEIxo5x4fgdSd8wClmuDItuK53QiweQzlBYKkHOwgKfpm3i7BFc/RVitG3CdfYu
         78HFi2wJ175XqqbDouLHqvylqtYwI+dCmQcX1iX34RToiZeEOldc0tNTDSmjPX2S+Y7Y
         59HA==
X-Gm-Message-State: APjAAAXyuJeAnbjVCrbCXHcqNgkQ7WD2PEljxmEkTG8//0FIAeY32a0g
	PSTJQ1s4pkjL9CaZZZrIXoA=
X-Google-Smtp-Source: APXvYqy77mssJLSgwRvGkpy9Dl3whl8R9gOTVskxIs7MwJ2VtW0wRxhRvJ2ENqRO1ZaX4VHpIhHLbQ==
X-Received: by 2002:aa7:9edd:: with SMTP id r29mr32432987pfq.14.1579117898103;
        Wed, 15 Jan 2020 11:51:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:9142:: with SMTP id l63ls5420034pge.6.gmail; Wed, 15 Jan
 2020 11:51:37 -0800 (PST)
X-Received: by 2002:a63:6f8a:: with SMTP id k132mr35587711pgc.70.1579117897686;
        Wed, 15 Jan 2020 11:51:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579117897; cv=none;
        d=google.com; s=arc-20160816;
        b=I3iu0x3XAhB43TNAFMk19e3auYKuNz/MymnG34izon3DsttCJhbfnafWLj+c9/H6UY
         qdOhBLverIpRd3lpGNQ+XwO90LWj4+ezW/LrnfeHW1KQm/GZ+8TjiiYTikQCXb5iCRKZ
         yXWIYoIzo9JvDpiteaQKCWjbL/E/rKLT9hNXYWq9i2S2gEwff84Xh89MhSzTobiYvidm
         lBGXPCY+qFs3R/LzVk8Z3IDXOP3qqqsqhuG1Ji8MTCfWwfLtV1PHWXuJ1Iq4MgA6v135
         ENHkBiGHEZj6QT0ylBRfDUwepv1aJ7PEeGefc2C4jBQhDplYIVxKbGE00+XqU+6uqTMt
         2aIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WrYAie2eRW6IOTWX2EXtM4jme3AXHDgWbVMHcdt6qOk=;
        b=xIYGhZa76cTdGht83zzcgsLYbQKmfdeCAtIrtcMcuwzMeFKIwf+c4BL6Lci+2GTr6r
         wslOKr72QRmxLOX2ngpwarG/Yffx6GzdWW+sFEsVlT5fWfVu+0kmpn27DODy+ALXCJT8
         CYVVYUUCJjfWNkAcMMLsO4eFpwl3jcoHynZh52I+6jbp8xFG6dgpCidwzvEeEh/NUb4c
         d3d/lmwNDMUZ5isFH82tZ/WCF/5saUaCRTD+U9pP3G0Vpep0Gkmmjs7ZG2uEux6irxsp
         tjTWpo1/wlhhzyeoAFApWmc4pIwVwMoZskBWUpzFK7NNrmlh2qLUsQ1DILo7Gy8TFmdN
         VBjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QeMscKv8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id y3si22679plr.1.2020.01.15.11.51.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 11:51:37 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id 18so16607771oin.9
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 11:51:37 -0800 (PST)
X-Received: by 2002:aca:2112:: with SMTP id 18mr1133436oiz.155.1579117897045;
 Wed, 15 Jan 2020 11:51:37 -0800 (PST)
MIME-Version: 1.0
References: <20200115165749.145649-1-elver@google.com> <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
In-Reply-To: <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Jan 2020 20:51:26 +0100
Message-ID: <CANpmjNOpTYnF3ssqrE_s+=UA-2MpfzzdrXoyaifb3A55_mc0uA@mail.gmail.com>
Subject: Re: [PATCH -rcu] asm-generic, kcsan: Add KCSAN instrumentation for bitops
To: Arnd Bergmann <arnd@arndb.de>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	christophe leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QeMscKv8;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as
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

On Wed, 15 Jan 2020 at 20:27, Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Wed, Jan 15, 2020 at 5:58 PM Marco Elver <elver@google.com> wrote:
> >   * set_bit - Atomically set a bit in memory
> > @@ -26,6 +27,7 @@
> >  static inline void set_bit(long nr, volatile unsigned long *addr)
> >  {
> >         kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> > +       kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
> >         arch_set_bit(nr, addr);
> >  }
>
> It looks like you add a kcsan_check_atomic_write or kcsan_check_write directly
> next to almost any instance of kasan_check_write().
>
> Are there any cases where we actually just need one of the two but not the
> other? If not, maybe it's better to rename the macro and have it do both things
> as needed?

Do you mean adding an inline helper at the top of each bitops header
here, similar to what we did for atomic-instrumented?  Happy to do
that if it improves readability.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOpTYnF3ssqrE_s%2B%3DUA-2MpfzzdrXoyaifb3A55_mc0uA%40mail.gmail.com.
