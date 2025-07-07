Return-Path: <kasan-dev+bncBCKMR55PYIGBBROHV7BQMGQESA7JWWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 45FD0AFB6F0
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 17:12:07 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-32b378371b1sf14895631fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 08:12:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751901126; cv=pass;
        d=google.com; s=arc-20240605;
        b=UY/WUWSo8lC7xJq8Ydj7iXyo/8HvLLFojGwUsnp0iee8LpF5qOpa1iwBIpuYSb4n6y
         oy5nAgttuGlPHbuXYgz0C27DnOLfWYKZAvaZzKN6JSNBZI5E0+KS8zid+h9AeSpGZraC
         mao4jZ1jdvHaFGLYVqXY5uDCDa84/rYvRK45OhuAG4InZ7a9oASZkl/6kEZWaPnlnTfA
         PCbNBxeMscu4HNB14kRSQFkqgUukNjhau9HnuRHC53rhaP3xme4S008/K4sxU5JHwdEj
         qmrdRraiFvT6TgSNhQmFif1ngle8K5BBQFGwgKjCPBfSE+8TL8AnOkSsBW24LVmU+ZPf
         Gu3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=7xTpYV2tRWMLRn+700MoFfuJBUfGaNO8p28vDtV1LIQ=;
        fh=G072iLqPMMB3N8aMh6Fm7qVWASBy8P/DV7lrDwe3+DA=;
        b=V7CwoktigIHBAEOMoyriurdmdqVElHwCcJbEObVS8bRo1prNdDBpPlGwGgnmqwpIym
         +VkPzLKd7zd3HKxRnjQBAiNj3LsMF9VH0PSOhXyR8C35R6zSPuTbb75rGTRF6X1nFC9d
         3+f+H2ha7XzWmKe0GP1VrAfYfs9xRnKgZA0TpLCT2DJK0pRJ7ZW4wz0yFHNMx0EvciKd
         6o5IZ05nJb/aPPpg8KYlBRp883z4XR9paKgFHRcvvN/RzWekHmDXJ84ZqcQh0MGitdJ/
         Ky31J6JVYLidBQrZKDY0WbN0Xtzd8Ff5PJVHOUUIX5G/TuY6G9yYJN5GuE0GV+u+uErB
         n04A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b="T/cNe0r3";
       spf=pass (google.com: domain of mhocko@suse.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751901126; x=1752505926; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=7xTpYV2tRWMLRn+700MoFfuJBUfGaNO8p28vDtV1LIQ=;
        b=fl6mK4PTk1UEnQy5aU2RXvQTLvvUWTxgZI2DcUXmDyA42j6s6LGMyLXSgrz0ofKXlI
         SaT581eul9trVcYhRXsihdsMG6g+/n+Rstw6i34okLonHLNTcEi/x7Pd5x0nWvLKmud5
         j4A+Cn2+luhJ2lq4ZE+HpJqbGZHEgIbvvBSDxBP7W2J+ZVH4Qc7T36XgBW8NYhpZrJ54
         WkPAqQwP8MqF0nwbcZ1wLXhMp//LBXSEc3rZkNLsnhVyhpaW31P85DJeMhoUsY2hOL3f
         6qj4VgQ/WtK7WTgNELw+HXBtAjxspolrN2ZMd0+9PdpGhlmvD6Pn6MJzN2o5jaH04sde
         IpfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751901126; x=1752505926;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7xTpYV2tRWMLRn+700MoFfuJBUfGaNO8p28vDtV1LIQ=;
        b=YVesA9JxtoNdUCEpdxaJtz6rKttsa5pbMpGL6kXdzt+cU4lKjCRDpiuKon+gslv/Xh
         JvCsyYWxpeqCU/qK+Gd4lvb8hGf36EpP1Um+GyEEkpnep0MXhvKC6QD3QwJcQbrYcgmR
         OWx6l7VTSPr0TlLtiko+cEaVKeuoxzaVDcpiMry1zKL5r9b78RS1szZWgdCRnTPg1MD8
         CLioyY4BPokvKvpqLhx/O5VbnPBl9tDEhQj59Rfc28Gae6SzjFo8BQhVGmfhV5HvCHeI
         +088pVFC7CtCUI9nYZ/34LeYrE3pUcw+nZk2FgO2XU72Zw9tYLrNBXmm8ykclBkcQ6oF
         rD2w==
X-Forwarded-Encrypted: i=2; AJvYcCW4tgForaqtRpi4PxRRIK+qa15U6g5a1WuP6aQrJcFVbzO2E2oDxIEdxogl/3FlXk8SS192ug==@lfdr.de
X-Gm-Message-State: AOJu0Yzq8+R2pLXk2bE606MtoInrpEgLx25LMLxlUiVFmk64tbHy1atw
	R3lBoEHOdtTKXMBd3z08C6Fz/ozrVn3DM/N+wFpjMl7RGvo4Sg1weSrY
X-Google-Smtp-Source: AGHT+IEelo0l95nH52XUZr6k+OIWk/oayeGfTYBmkSSqo5SNLXbjs0HZnUqP3A3mP8QOvvUccT8LAw==
X-Received: by 2002:a2e:a549:0:b0:32c:a097:41bb with SMTP id 38308e7fff4ca-32f199891d3mr23241091fa.5.1751901126056;
        Mon, 07 Jul 2025 08:12:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfGNGJ5Cij4RSuwkRRKa7Im4xmKFxaazQZwRmk7PB+8pA==
Received: by 2002:a05:651c:31d8:b0:32b:2c5f:c18f with SMTP id
 38308e7fff4ca-32f113bd89als6414181fa.2.-pod-prod-02-eu; Mon, 07 Jul 2025
 08:12:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVg+P7Gl8TwZIqxfdS3Lgz6fYWwDpAZxHSC7IaUKXFp+MyJCrBnPj9Eh98cUWYT5PEiT+ePfkZMFXc=@googlegroups.com
X-Received: by 2002:a05:651c:410e:b0:32b:9220:8023 with SMTP id 38308e7fff4ca-32f199c4e7amr15937851fa.12.1751901122784;
        Mon, 07 Jul 2025 08:12:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751901122; cv=none;
        d=google.com; s=arc-20240605;
        b=Qyln0zVhtIVJ9qpvDlmzxOOTJDcPkwWt5bSV8r+U/+YsONODGoWxJcXh2qINlS57OC
         HYWG/kKQ8HNeaPESXLsz3tpphTbMaNjzyz0WCzgtJrk1aAP3vBFVuOs/2+c2Tpa4i7Vh
         i4z+LN5ouLdtJh3uQmhM5xSsVwKMPfFQOED6it9FS98/F0JZj7JQ36CcuZbZBPPgvQY8
         o5IMQc4kyvfScOq4NEQQUz5g0lvt94/BdwqS9JJBTk7H+osRYp6D/H49idBkPxkXEmnj
         e4zBX/V+wxVf/oNf+iqeFqodp7ld0LGWmihMItYfmdgnnxsCR4i8aqx+9IcMF9YaZB7Y
         w8Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2BUkMO3y8xtFeb8SJ1RGkSZs/uXuWNfET6KZvqytQMs=;
        fh=PChYEpvqLay/qWlRblerNz0osVSrDG5QtMwnhxGIoH4=;
        b=SjpCcT3JWxWOCjjm2EPH1ah6Lb2diMxPcwHRV9kHbwihoqKB2QMxTbTYFTP1QZMrA3
         /TLZtimie6L+P4CJ13cLyc7reQNYOJDKiK5/cG3mGPqjA54xehUIGjSWzrrIadgEliwV
         0b1E46eW3aAhW3CSRRoS5wWq2JSfP1qH3TF5jOx4woWwoE1p6eEDC3Uui1Joyhu6/zDE
         xdeGxi0Ag+r6KZ2glwJdWQgJ+XBaT6/hI0jqvi9EA/TMLMXFXHzAQHGAKugpWWCf8iY7
         9nOyPuhS/wIKS87SRxsU1B3I1er2T+DA2FnOfHff1zUPOivIVL/eJUi1VFTKfzw22d/U
         TONg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b="T/cNe0r3";
       spf=pass (google.com: domain of mhocko@suse.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32e1b20b837si2178561fa.5.2025.07.07.08.12.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 08:12:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-4537edf2c3cso35463985e9.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 08:12:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUmxzD18MeJ3PgQkpMK3Ynx1udWO10Gv2KlxZ9uAqosuzzHp3zPb95c1TXGVTF2Ozrbs8jHKwlgEPk=@googlegroups.com
X-Gm-Gg: ASbGnctQ6A4vX2PsOFRbEKAR/0H0eTP8ZNcdkbSYM9PgQkrUYNGsLo+/wZNNA7HS3fo
	E6lnq/lXoSjiyXR4d3wWV7epZy59/5s02WXi79Br/BtK1IsxP6E52gtLx9mxTorlvScmj3tsB/Y
	HjqnGwfCeKmCCi1d/KsIktlFqMnBiPnOjt/qAa34qR2WxVfxbScp9LYAkMO/7/c5M8duYliU4AV
	1J2cDbdsEPZBPfoJ1L5T5f0xjjJ1Cp3pGPNA7Gc6Gz9p+/qCgr4aACM+/wGY0GCBpFLXEIJsLsR
	2kMaHt+MpLTSEvgipkqfIsXR/Eo5WqJS3TIIEhFNksscXX9c4cctUZEcAF+PlqRgFW8k/GxDguh
	gHKlT9KMdVw==
X-Received: by 2002:a05:600c:4745:b0:453:d3d:d9fd with SMTP id 5b1f17b1804b1-454bc5c4004mr77773035e9.12.1751901122277;
        Mon, 07 Jul 2025 08:12:02 -0700 (PDT)
Received: from localhost (109-81-17-167.rct.o2.cz. [109.81.17.167])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3b47030bd58sm10720459f8f.18.2025.07.07.08.12.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 08:12:01 -0700 (PDT)
Date: Mon, 7 Jul 2025 17:12:00 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alejandro Colomar <alx@kernel.org>
Cc: Marco Elver <elver@google.com>, linux-mm@kvack.org,
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>,
	Christopher Bazley <chris.bazley.wg14@gmail.com>,
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Harry Yoo <harry.yoo@oracle.com>,
	Andrew Clayton <andrew@digital-domain.net>,
	Jann Horn <jannh@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [RFC v3 5/7] mm: Fix benign off-by-one bugs
Message-ID: <aGvjwDqRP1cPaIvX@tiehlicka>
References: <cover.1751862634.git.alx@kernel.org>
 <740755c1a888ae27de3f127c27bf925a91e9b264.1751862634.git.alx@kernel.org>
 <CANpmjNNQaAExO-E3-Z83MKfgavX4kb2C5GmefRZ0pXc5FPBazw@mail.gmail.com>
 <aGt8-4Dbgb-XmreV@tiehlicka>
 <g6kp4vwuh7allqnbky6wcic4lbmnlctjldo4nins7ifn3633u7@lwuenzur5d4u>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <g6kp4vwuh7allqnbky6wcic4lbmnlctjldo4nins7ifn3633u7@lwuenzur5d4u>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=google header.b="T/cNe0r3";       spf=pass
 (google.com: domain of mhocko@suse.com designates 2a00:1450:4864:20::32b as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Mon 07-07-25 16:42:43, Alejandro Colomar wrote:
> Hi Michal,
> 
> On Mon, Jul 07, 2025 at 09:53:31AM +0200, Michal Hocko wrote:
> > On Mon 07-07-25 09:46:12, Marco Elver wrote:
> > > On Mon, 7 Jul 2025 at 07:06, Alejandro Colomar <alx@kernel.org> wrote:
> > > >
> > > > We were wasting a byte due to an off-by-one bug.  s[c]nprintf()
> > > > doesn't write more than $2 bytes including the null byte, so trying to
> > > > pass 'size-1' there is wasting one byte.  Now that we use seprintf(),
> > > > the situation isn't different: seprintf() will stop writing *before*
> > > > 'end' --that is, at most the terminating null byte will be written at
> > > > 'end-1'--.
> > > >
> > > > Fixes: bc8fbc5f305a (2021-02-26; "kfence: add test suite")
> > > > Fixes: 8ed691b02ade (2022-10-03; "kmsan: add tests for KMSAN")
> > > 
> > > Not sure about the Fixes - this means it's likely going to be
> > > backported to stable kernels, which is not appropriate. There's no
> > > functional problem, and these are tests only, so not worth the churn.
> > 
> > As long as there is no actual bug fixed then I believe those Fixes tags
> > are more confusing than actually helpful. And that applies to other
> > patches in this series as well.
> 
> For the dead code, I can remove the fixes tags, and even the changes
> themselves, since there are good reasons to keep the dead code
> (consistency, and avoiding a future programmer forgetting to add it back
> when adding a subsequent seprintf() call).
> 
> For the fixes to UB, do you prefer the Fixes tags to be removed too?

Are any of those UB a real or just theoretical problems? To be more
precise I do not question to have those plugged but is there any
evidence that older kernels would need those as well other than just in
case?

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGvjwDqRP1cPaIvX%40tiehlicka.
