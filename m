Return-Path: <kasan-dev+bncBAABBDNFX3EQMGQEC7GGQWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id A42A9C9D800
	for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 02:29:50 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-640ace5f40dsf6598239a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 17:29:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764725390; cv=pass;
        d=google.com; s=arc-20240605;
        b=TwhxcOB6jSoWt2k+/Go8jyy8H+nhla57nDmk+niY0SeuHUimsjQX2POU2AjAfvtllL
         LwBs7/keQH0qy/Jdeg/6eULf5fZVZlKtEuCLRZXLWDuhV3/xBdkUeIkPllP47xeiD4ew
         FAfbIhXbAVhAy7Ov+ZlUZoSlZecAtT5QaG2C/Oi1VshhwhWLVH2QHyKXRRYI+tmhPno4
         hPBdwSIERERajYqIFw3ogZkFHHwu4OFrdi2nOY+31F7RU0EReHat7dm5xlW/uWLvahcm
         xAlpgL8OGH1ZFhjrNAvX6gvXZC9ahFvgB1RM3P93uyYp4y0irWpRLpPMoNtIkB+UlJEw
         gy4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:cc:to
         :subject:tls-required:message-id:from:content-transfer-encoding:date
         :mime-version:sender:dkim-signature;
        bh=IwqZdO0z/3iym8fD5m0LtDv1ssydmF7bIF0WtAEOelc=;
        fh=+09dlSeg2L1J2wP2N3HGncw9WxqaFrbn1keo7R3i0NA=;
        b=OQ1Us7IYcHB39/uzZYMXbX8mwT/2EvFEZDxpjRQgUfpnnU3Ikwh3kk2STIVSCGtlpX
         TEpKl89pLOmyVvn76gHVwY1OdnJj9iZio/Zt4LO0CFHuT4/SO2Nb2KJ99XjdxFYpLu/G
         mex9HPeC9cYqBEQw/WoQFTLW6Xj3PtOLEEhhXhUijMyM0w8rTlVINCqL4V0a9+9H71J7
         MDxYy7yMvJegGQR2f2smZOpK6CVjDoP2iv9uszR8HsLevryRYEwM+xM/cmELbrq37RX6
         Hlk4d/IYTi7HGZGJmCy2ypr+vY7sK4TyK3wRIK6C2gaC+v09uMJzgpTOhRSDa173QWb3
         zg9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=grU07+R6;
       spf=pass (google.com: domain of jiayuan.chen@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764725390; x=1765330190; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:cc:to:subject:tls-required
         :message-id:from:content-transfer-encoding:date:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IwqZdO0z/3iym8fD5m0LtDv1ssydmF7bIF0WtAEOelc=;
        b=P9BbA/bXzHZgMvOvdmqJ3WVcBvytHly4hbuKaThYEdoDXDguAef4XHiR2AaNyNett2
         +VApXVD0majyxC/rPBgs+7R7i6OXKaDL3g7MEzIBrOdcUoHoOWlep+axxZMiq3+2LaXX
         AiIi0zz4HeGeVqIsHKQ0ZJS8I6JCzvHbUTGv/RLUzpRbbhGSs6NRaBwIWU4JRFNGtTb/
         4Ezucf/5LI0E42K5VChp6cmR3CuHdK1/dEwPaTySWBjCUTJ1TAXPRxtYe0zjn3jgZNyD
         j31b/Pl1YpDimbcsJrnqxsQJmSL/t+y+9V2aF2xjFwtUGLa28gSth+QjRGESPoQe5aXb
         +87Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764725390; x=1765330190;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:cc:to:subject:tls-required:message-id:from
         :content-transfer-encoding:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IwqZdO0z/3iym8fD5m0LtDv1ssydmF7bIF0WtAEOelc=;
        b=S7t4p8IBO6bWla5kkeU+q1RosIczy+7x8egl/HuE6johCA7U64P8lI/VY1sH/Y1e1N
         32YCZ1PS68Tgk6H7mQGq5HfI22JOqF9ZIBFwdhvR5+gq3YQR+3+pLxkoDUISAeVOMyvd
         faZ1Ijlb0UF9EkiAypvIb9etOfgTpmWHOLRjiYXBZ3D/NgjFPXoqXprp2NaVnOB/tYXm
         2/Fm9PDzOVUoSkUzQ4e/nfiW+qERqIsOUegYhQ6+IndXlmqsRD4LYrD6N3XxtJkBhY5s
         ACUYhlrxpF+27g9l6FWza3VH1+5dUABsipGrBOxFYmv7DkZSLiZ0PAtTkzUsmsWbBrge
         6iNg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOXc0lLDrfxRwT9uTrCzcStJg4t/lxZXzcwiX85o734nywy6MV7k/JKvMVBcWcJDW26a7hjQ==@lfdr.de
X-Gm-Message-State: AOJu0YxtXk4uq0y2a7Fr+9Is1C1DgJYtV5gumUeeWl2JOELkKsavCydn
	mcXZRS9aQCprWeQoP4g8B4q71sUMbSSWa7fAq2eiHqTe6XlRGzQbebi+
X-Google-Smtp-Source: AGHT+IFmJslfzFRUjrc4YE0ahDqaYsgeCs/LmI5YbFNMmExHpSp77nVS4SAW6G4Up3+c5SGbcaAwgQ==
X-Received: by 2002:a05:6402:2750:b0:640:b3c4:c22 with SMTP id 4fb4d7f45d1cf-6479c46a962mr369127a12.18.1764725389859;
        Tue, 02 Dec 2025 17:29:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZT4ndau7aLBX+wK5WS0zaC3tDVjb7xFKonmZ3KM27cRg=="
Received: by 2002:aa7:d347:0:b0:641:8d41:d6f5 with SMTP id 4fb4d7f45d1cf-64749b5595fls4299112a12.2.-pod-prod-09-eu;
 Tue, 02 Dec 2025 17:29:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUhtiTfmOtxEQ2cTk4XC5JiNVR1kVd1yMVoDvNelUd65uOr5Ip9V6r1OM7lQ8d8HSq5OVWisDbPnww=@googlegroups.com
X-Received: by 2002:a05:6402:35c8:b0:643:18c2:124e with SMTP id 4fb4d7f45d1cf-6479c3d59e9mr384791a12.7.1764725387897;
        Tue, 02 Dec 2025 17:29:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764725387; cv=none;
        d=google.com; s=arc-20240605;
        b=Flr25dr6W4qqMjbkjvlKJZLEhpyqSVae7F4N6sjQUEytKtYl0znvKJFpR9KjBSlShG
         ds+iGd9TJ9Yyc/WoqlMNr0GSFxYVKy5MdEcZRoZvZ/RzAlbeM7Z39Q51J6wVY2TNEGQn
         u1wlNgEQFfmpOLesiCYWF86ESSo2ggs4WQ7Eg/jR+S6F9MHPCgmo5/+C1N3E1rF/B/rv
         4qxNpzk+j02FQhdtndVtpSlZ0geV8mMcyazJn6nn/EYrO+sKXOWbfwgrla3sCP0/SZE6
         uQICkrCDHO8fIR1a5+BW3UIugZyRgk0kakxJjvArt/x1CFoJrMAsb0c8I6d1J0ygn3dj
         0Bkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:in-reply-to:cc:to:subject:tls-required:message-id:from
         :content-transfer-encoding:date:dkim-signature:mime-version;
        bh=pTga2TAwNScG/3kVeor5h8KiVEoB630/ynsQmQFDxGs=;
        fh=xugCHoOd3IddHEPvsjKKGCmOQynEIZ/9GDw3qlw9y9g=;
        b=JfjiIx3qFFzycuiaurr0oV0Quu8WVGEYzYt21dBbeR+rHFazxEH5Dct0C7tznjeVMb
         y08IfGuSCE64gG/6Ngiohj33UHhczrW5eNbEhYCkAG4JlLsWWNeh2QtT0qIg2E1Z5mu/
         0SEsbpfBKj0l6lmCQszvfcy1jWiOsQmbYq5r6XlrCOi1XxfI61JGJFu+rgUcSnjZkRQl
         +0pRbC3UyyD0ZjcQDRfDfA87R3E9q1iUZUqGlo+y5VneP8+9RdtuLyVx0yDS1atTwq+X
         Fbjd+lReNSSL7RDshXAKptTUKIEyDj7EC/AIRyIdNNk+DnbLkkk1U4Kph0bi/P3LPhY1
         labQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=grU07+R6;
       spf=pass (google.com: domain of jiayuan.chen@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta0.migadu.com (out-171.mta0.migadu.com. [91.218.175.171])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6475102acb4si258253a12.6.2025.12.02.17.29.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Dec 2025 17:29:47 -0800 (PST)
Received-SPF: pass (google.com: domain of jiayuan.chen@linux.dev designates 91.218.175.171 as permitted sender) client-ip=91.218.175.171;
MIME-Version: 1.0
Date: Wed, 03 Dec 2025 01:29:36 +0000
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: "Jiayuan Chen" <jiayuan.chen@linux.dev>
Message-ID: <e5e5bb62c5a40d2673cc1233860143571aab9d12@linux.dev>
TLS-Required: No
Subject: Re: [PATCH v1] mm/kasan: Fix incorrect unpoisoning in vrealloc for
 KASAN
To: "Kees Cook" <kees@kernel.org>
Cc: linux-mm@kvack.org,
 syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, "Andrey Ryabinin"
 <ryabinin.a.a@gmail.com>, "Alexander Potapenko" <glider@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>, "Dmitry Vyukov"
 <dvyukov@google.com>, "Vincenzo Frascino" <vincenzo.frascino@arm.com>,
 "Andrew Morton" <akpm@linux-foundation.org>, "Uladzislau Rezki"
 <urezki@gmail.com>, "Danilo Krummrich" <dakr@kernel.org>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
In-Reply-To: <202512021522.7888E2B6@keescook>
References: <20251128111516.244497-1-jiayuan.chen@linux.dev>
 <202512021522.7888E2B6@keescook>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: jiayuan.chen@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=grU07+R6;       spf=pass
 (google.com: domain of jiayuan.chen@linux.dev designates 91.218.175.171 as
 permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

2025/12/3 07:23, "Kees Cook" <kees@kernel.org mailto:kees@kernel.org?to=3D%=
22Kees%20Cook%22%20%3Ckees%40kernel.org%3E > wrote:


>=20
> On Fri, Nov 28, 2025 at 07:15:14PM +0800, Jiayuan Chen wrote:
>=20
> >=20
> > Syzkaller reported a memory out-of-bounds bug [1]. This patch fixes two
> >  issues:
> > =20
> >  1. In vrealloc, we were missing the KASAN_VMALLOC_VM_ALLOC flag when
> >  unpoisoning the extended region. This flag is required to correctly
> >  associate the allocation with KASAN's vmalloc tracking.
> > =20
> >  Note: In contrast, vzalloc (via __vmalloc_node_range_noprof) explicitl=
y
> >  sets KASAN_VMALLOC_VM_ALLOC and calls kasan_unpoison_vmalloc() with it=
.
> >  vrealloc must behave consistently =E2=80=94 especially when reusing ex=
isting
> >  vmalloc regions =E2=80=94 to ensure KASAN can track allocations correc=
tly.
> > =20
> >  2. When vrealloc reuses an existing vmalloc region (without allocating=
 new
> >  pages), KASAN previously generated a new tag, which broke tag-based
> >  memory access tracking. We now add a 'reuse_tag' parameter to
> >  __kasan_unpoison_vmalloc() to preserve the original tag in such cases.
> > =20
> >  A new helper kasan_unpoison_vralloc() is introduced to handle this reu=
se
> >  scenario, ensuring consistent tag behavior during reallocation.
> > =20
> >  [1]: https://syzkaller.appspot.com/bug?extid=3D997752115a851cb0cf36
> > =20
> >  Fixes: a0309faf1cb0 ("mm: vmalloc: support more granular vrealloc() si=
zing")
> >=20
> Is this the right Fixes tag? I didn't change the kasan logic meaningfully
> in the above patch, perhaps it should be commit d699440f58ce ("mm:
> fix vrealloc()'s KASAN poisoning logic")


The tag you provide is about shrinking but the issue I encountered was abou=
t
expanding(Grow the vm_area) and kasan_unpoison_vmalloc() didn't work well w=
ith expanding.

Thanks.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e=
5e5bb62c5a40d2673cc1233860143571aab9d12%40linux.dev.
