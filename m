Return-Path: <kasan-dev+bncBDW2JDUY5AORB2X6X3FQMGQEIEDWBGA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GApsOmu/b2kOMQAAu9opvQ
	(envelope-from <kasan-dev+bncBDW2JDUY5AORB2X6X3FQMGQEIEDWBGA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:46:19 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8579A48CC6
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:46:19 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-47ee8808ffbsf42359435e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 09:46:19 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768931179; cv=pass;
        d=google.com; s=arc-20240605;
        b=QP+JVqXBH+pJyU3v4K5T1+COPWiDTIiOyt8q30AdpgYXVf7mmaIqjPo0MTivLPbAN6
         TBP2oiC/JUsCMLP5LOFeXxs9fybNJ/oBKVpgtKFfspUcG+Zl2cqgOEtfAYdfI79kLDQ2
         P3/xwJw6Lmcn8n1zQ3On/qe+MFlmnzavC/zYYZRfUzmvEx0yeAUnaqB+mLNzY+PkLyts
         dIHbs0VZsXqkhtKEMTtHAqYhWyAFZUZfaz3UzQmNpkfQWJPo6ObdbZOELJfL1zjjA94w
         0EBdHIcqXH8UvITJ21fmc3AcFC3xZ8fgp5V5Y/deuD7RWvfg5+8pRmhNHxbixQ89nymS
         ThnQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=C+4mUCim0kllO8zWtQynD8MqT0eMEYdtluhH2nyzgeA=;
        fh=BEMgTKHeKGX5QVhf9AdAzpp6di3HI3BKM12z3goiXQA=;
        b=WLjX2oPDiG9+G1g+CVN4WC49Cf1MVvCS5M29tSGs2Phlkfm3QWZRBT7T3McrB0i/6w
         g4YNIRmYC56Is8IG9zwMiMdMOAZNBRQLWWhE87+vfo8ShRGnPKrjM1XvY2wUqy4eO/eP
         Z1ssGSu9VhyW7XCfYb8xj8nKjdSsHUIVQc8KrUYxQGHVhdRuKg9WMNgG/H3Nz0EJwau6
         I8tvT+sAWfNmdAcavNdmD0mbc5napQ+yXLej/bG4YzHPiwIN8lmPVPV9cyDYHvUyTlhJ
         mk2QawTQp7S5Hu1M3wiIOaESnRB3rXqXmAsO7FmHEQ7zMVnU3QjJB/mexMHd28Vg6AuS
         Zm/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XFU4uR1U;
       arc=pass (i=1);
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768931179; x=1769535979; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=C+4mUCim0kllO8zWtQynD8MqT0eMEYdtluhH2nyzgeA=;
        b=uB9aWGJu1sJwy7X6FSxVRFn7JNff0k0v+AKQi8IOOmxeg33S6lPsSykmuWXPAswWas
         3+Dk9cFh7rw83dudjhMzxHU3z++BMJUY8FOBR4/jWl6yvKv+3VKaTmZDWSHX1iSi93Mv
         XiJvp8JdcK5Vf3ykO5fpJly7dnOvTl/Sb5MjsmVRuJHh/2Z9Lt94soWJwlZOdnE2oqaA
         9HEI9rhcYjxUsHYIllGX2BgSTAUApo0Tzn1d1QNCWDse8zf4AKZQsq4mc9bbJxN+QtOJ
         eMeBvWzq1308UhkgdZtQNUmGunkZxt/ow+av2b2ROWlBUP7qLmDhvh+ciqAiZiOK+1r0
         5Ifw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768931179; x=1769535979; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=C+4mUCim0kllO8zWtQynD8MqT0eMEYdtluhH2nyzgeA=;
        b=bfbDANtJIZyBYPnxeM8mzRVGWF4O/EW/U6gAeaAat2QBUrN/QLDJfZOZ0DyM4EhzND
         gFxcVZ/9xSotPqG8Fer53jl/wLI9saW3OJc2mOIj4vMF4MPqaJrjTvUG+YzHLiinfrsR
         x3F69YxwOIMzlDIRtM3wqa5rQZpIQE73I/O7ySw2rp0FPafCuURm0HzOtiIg3r2iv+oI
         zybT+QgoCt8X/v0ZtL/o0D3Lf7+WIVidOm41WY37hSvd1HPOHGZlA+y0lR+EvoC5rWBz
         i0hyST+KP6NX3LaMjgA0iEIqL7W/zpaRWiZkDu575h1i0AtNRnxPQK3QgOQQIfaBsTRC
         htXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768931179; x=1769535979;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=C+4mUCim0kllO8zWtQynD8MqT0eMEYdtluhH2nyzgeA=;
        b=Q8jMNm0lsDmCpU+n+nD7OctARL3tDoaq+a41o2HyFqIJajmh64tHC92zf+Q23GTQhg
         0aTEkJheOtxJZMuJLqeFS5o6YB8muqx7fiZLO2rVQkpH4xw8aPPC8D2TxGkaAkmW7uAl
         u8Te7ruU010oTMDfpV6yApIqGLdLCynqpBYwDuwk/8TwgSThzcxr1ziv9Lycwsil+ge0
         um694DjucAbuyZQoghl9GpcLDzZ4B4GCn81NIrpF1MaXDWXq91wj7nergQrOeB2Xm6EA
         1yRQilTwMf9rkA5R89Tc0S9Fjf6b2xUsyb3r1dfWJdt82fGX2q71tAkw15T9SyJEDZ2p
         TbDg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCUxVfFdZXrjkzO6bdvqzyNbk8iC45ZvZ0vSZxowrgxI4uWsCeeMcmbFG2bkwy6o8EOZHmukgg==@lfdr.de
X-Gm-Message-State: AOJu0Ywk9biy0n9Rrr54VTR72gGEFbH2KTuvpP1NO/TXnYEmQDYDHcuB
	07iOtnW+cmt3CCEYzUIFCl+CO90BNlYdKJE0EFHjuU3g5sd0rGmNaZFD
X-Received: by 2002:a05:600c:3d8b:b0:479:2a09:9262 with SMTP id 5b1f17b1804b1-4801e30b49emr170613715e9.9.1768931178705;
        Tue, 20 Jan 2026 09:46:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ElJYyh7lBhj2HHRJ80R0qlU87EZ3HKGu42AjTKdSTGLw=="
Received: by 2002:a05:600c:3110:b0:477:5582:def6 with SMTP id
 5b1f17b1804b1-47f428efa4fls35176945e9.1.-pod-prod-03-eu; Tue, 20 Jan 2026
 09:46:16 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWDgXaVA5rAevC6UcVqmYtO63z4P85xBCm/e0H7udy20MrlWFIFA0h+Pn5R2hrMTGKghNIPHr6SjEA=@googlegroups.com
X-Received: by 2002:a05:600c:1387:b0:47a:935f:618e with SMTP id 5b1f17b1804b1-4801e30ba55mr226387455e9.15.1768931176337;
        Tue, 20 Jan 2026 09:46:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768931176; cv=pass;
        d=google.com; s=arc-20240605;
        b=Heizwu9OpfxlxK3WCFmRD6slLC4Uo6scUiue414M9BMn35tYYDUj0xGA6CuFx4G8pU
         73h4Kn8RB0AXHFrXTiLWOvwelPvOPP1ccO74Pr/bUccZe289ytyV2KKOvesG9Fjhh82B
         Sv2xFRzs8JkScPCA7HGuawW92g0pwk35pK7q1w0SxaXFUwKPMtwYcC4XxOZ2jO3vo8qr
         iOXZGr+Yuq22VTxO0Nsq2iAp5uDIhWXYB9MVlEllRSEFf4vtwYV0clDgAaicfwWI1dmH
         7GcSrwqKuU8DaD/Tiz38C7g3YWqFMWgr5qwivpONdvA1nCM1rDigBK+Ulid0XCn+3Dyr
         uW8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=S62j0SHPNW708eY63qC28hPGcjYC7bAFOz0DSzigrVs=;
        fh=FlDN30UzXZgtCFu9qB8WxFEfLT+k9op5IbFrFc9yJww=;
        b=IdIjl1jnUVPEJGtKhadLIw8x77/HwDxmyIc7ntiFCof1DfF9vhExFKJB7YK9jPgNx1
         64Y3uxyl5CKYlZYmNCXbhJpl90gxPWoVveQaB151dMijtcgxGNfdmS7vDEpaZVGLASFx
         9t5gignfTTqKkoKLmRRitrxgP2idjP18BaAfMrJoRhSntc2CGEu4zYn5OhVhyG44vw9A
         b5jWNT+4U5cY59vymPh8BJu5FCtZLPPJhU+3sD1QT9QMKokqOxx44tDuXziKrKwOkHpL
         HyQkBF4X/xYkLLW+L7cQXlDaaiDZGTeQ38bnka2zAm9aKIgvl3EP2uqwHvGiNDQiUocJ
         +/rw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XFU4uR1U;
       arc=pass (i=1);
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4356992141csi276419f8f.2.2026.01.20.09.46.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 09:46:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-4801c2fae63so36768855e9.2
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 09:46:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768931176; cv=none;
        d=google.com; s=arc-20240605;
        b=U4ep8AZL/auDpYOvPoWVOJY03ojE1TF/gWiceV3A70NS19dCjGSiYnyUCnStVReETX
         g/kiKxx4/tpmZMnDknFxZC7uArtYO1EtxTuBvyzjmPJ7zKT2xS26Jmq2KVHnvh+D0zHG
         dux2tHG0Nkx3Pv7HK2MYIKq+PL60NrqBR8skNnqbOXW1cyzN9vTHkuYZjRJPxTfpBX6p
         cGZcG/yTas3uRyoVagblf9E6zGedRCwj4ho/rrxWEiBsZpDrAdzulY5ak6xLw8ZT2nyH
         ak1khDMZyhPQMMkhcMiV27QjzousOWw4Dq6ulMUuLah+4GG9XJRGpdnFHuqa1o+swAgE
         4olQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=S62j0SHPNW708eY63qC28hPGcjYC7bAFOz0DSzigrVs=;
        fh=FlDN30UzXZgtCFu9qB8WxFEfLT+k9op5IbFrFc9yJww=;
        b=ffDomzJxieYT62WxM3/gW9WwxEB8r5WHK3gL3rSqaEmGA+O6iHQHyhAPnFy/aVEFO3
         xiga2xZ07GaCl3507G1kTZcNxye079CEq30k8DG+W6SnK+vkQXVHUXmPScm1d0rMa3VS
         A/OeBafHIurbTjs5UbXW2no9Rufwd0LuHWFcFaU/d7a+aVrXlSxOTsfYe7kMS3ZdS+3S
         5WPUzofcTU32JERHW7+qfdqTFOylIAIfNqzDPQ5Bqfhc0lnMcU4YRLEeL6/gZXbDsPno
         AiFWQLkbp1R+lLV9a9gZNaHuwZaOaAI6ynubLG5vccgYtnGLVAaLk0Ujf7NHcivFZrsH
         krxA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCVBcLfJ0Pm7AY7S20QnS4YUwcLWqishGuiJRQJqZozGycJtJel8NRlFBpE9L21xb+mQpoGaTnC2nOM=@googlegroups.com
X-Gm-Gg: AY/fxX5PhBW7Cj6ECfjdmwBLIpymN991QEX0vCHFE7/xD8n47abG7xnh/6fzWCS/6Jm
	SIzTj274nLaEhdIZiASgc9X4c7kWiDATVAd451hD0zAvw6Cd16QvMWw7XTL0KTijA4z6Bm7pNAt
	zCKl2Esh2L3bmCfCuT5Tx5LKw90BkJ4ZWAXSJAR/1TX1Ir0ifRUuIN5CfhHHGVc6BPtzZcwR5x+
	jbdfgmd0G2jMV5alzLO2l6sbFjjnD19O1q7r+io20EK02LTM+hLTFJwlE92kJcKAl21GrQXXCb0
	r51W2uudQuRd6ZcKQpb9eKF5jlMVGw==
X-Received: by 2002:a05:600c:1387:b0:47a:935f:618e with SMTP id
 5b1f17b1804b1-4801e30ba55mr226386785e9.15.1768931175524; Tue, 20 Jan 2026
 09:46:15 -0800 (PST)
MIME-Version: 1.0
References: <CA+fCnZcFcpbME+a34L49pk2Z-WLbT_L25bSzZFixUiNFevJXzA@mail.gmail.com>
 <20260119144509.32767-1-ryabinin.a.a@gmail.com>
In-Reply-To: <20260119144509.32767-1-ryabinin.a.a@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Jan 2026 18:46:04 +0100
X-Gm-Features: AZwV_QgHEFU4vEPzoSPaqq3jpo5TVtLgMu7Szxs9QJWFvb1rbWBsdNTSzpLq_Nc
Message-ID: <CA+fCnZddq=S0H5qXZ_CLSB3Y1cNw7nY4AYTBsGRR5DmY5+=paA@mail.gmail.com>
Subject: Re: [PATCH] mm-kasan-fix-kasan-poisoning-in-vrealloc-fix
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>, 
	Maciej Wieczor-Retman <m.wieczorretman@pm.me>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Uladzislau Rezki <urezki@gmail.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XFU4uR1U;       arc=pass
 (i=1);       spf=pass (google.com: domain of andreyknvl@gmail.com designates
 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBDW2JDUY5AORB2X6X3FQMGQEIEDWBGA];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[gmail.com];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	FREEMAIL_FROM(0.00)[gmail.com];
	RCPT_COUNT_SEVEN(0.00)[11];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[andreyknvl@gmail.com,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[linux-foundation.org,google.com,pm.me,arm.com,googlegroups.com,gmail.com,vger.kernel.org,kvack.org];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 8579A48CC6
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Mon, Jan 19, 2026 at 3:46=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail=
.com> wrote:
>
> Move kasan_enabled() check to header function to avoid function call
> if kasan disabled via boot cmdline.
>
> Move __kasan_vrealloc() to common.c to fix CONFIG_KASAN_HW_TAGS=3Dy
>
> Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> ---
>  include/linux/kasan.h | 10 +++++++++-
>  mm/kasan/common.c     | 21 +++++++++++++++++++++
>  mm/kasan/shadow.c     | 24 ------------------------
>  3 files changed, 30 insertions(+), 25 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index ff27712dd3c8..338a1921a50a 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -641,9 +641,17 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, in=
t nr_vms,
>                 __kasan_unpoison_vmap_areas(vms, nr_vms, flags);
>  }
>
> -void kasan_vrealloc(const void *start, unsigned long old_size,
> +void __kasan_vrealloc(const void *start, unsigned long old_size,
>                 unsigned long new_size);
>
> +static __always_inline void kasan_vrealloc(const void *start,
> +                                       unsigned long old_size,
> +                                       unsigned long new_size)
> +{
> +       if (kasan_enabled())
> +               __kasan_vrealloc(start, old_size, new_size);
> +}
> +
>  #else /* CONFIG_KASAN_VMALLOC */
>
>  static inline void kasan_populate_early_vm_area_shadow(void *start,
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index ed489a14dddf..b7d05c2a6d93 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -606,4 +606,25 @@ void __kasan_unpoison_vmap_areas(struct vm_struct **=
vms, int nr_vms,
>                         __kasan_unpoison_vmalloc(addr, size, flags | KASA=
N_VMALLOC_KEEP_TAG);
>         }
>  }
> +
> +void __kasan_vrealloc(const void *addr, unsigned long old_size,
> +               unsigned long new_size)
> +{
> +       if (new_size < old_size) {
> +               kasan_poison_last_granule(addr, new_size);

I wonder if doing this without a is_vmalloc_or_module_addr() check
could cause issues. I remember that removing
is_vmalloc_or_module_addr() checks from other vmalloc hooks did cause
problems, but I don't remember what kind.

> +
> +               new_size =3D round_up(new_size, KASAN_GRANULE_SIZE);
> +               old_size =3D round_up(old_size, KASAN_GRANULE_SIZE);
> +               if (new_size < old_size)
> +                       __kasan_poison_vmalloc(addr + new_size,
> +                                       old_size - new_size);
> +       } else if (new_size > old_size) {
> +               old_size =3D round_down(old_size, KASAN_GRANULE_SIZE);
> +               __kasan_unpoison_vmalloc(addr + old_size,
> +                                       new_size - old_size,
> +                                       KASAN_VMALLOC_PROT_NORMAL |
> +                                       KASAN_VMALLOC_VM_ALLOC |
> +                                       KASAN_VMALLOC_KEEP_TAG);
> +       }
> +}
>  #endif
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index e9b6b2d8e651..32fbdf759ea2 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -651,30 +651,6 @@ void __kasan_poison_vmalloc(const void *start, unsig=
ned long size)
>         kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
>  }
>
> -void kasan_vrealloc(const void *addr, unsigned long old_size,
> -               unsigned long new_size)
> -{
> -       if (!kasan_enabled())
> -               return;
> -
> -       if (new_size < old_size) {
> -               kasan_poison_last_granule(addr, new_size);
> -
> -               new_size =3D round_up(new_size, KASAN_GRANULE_SIZE);
> -               old_size =3D round_up(old_size, KASAN_GRANULE_SIZE);
> -               if (new_size < old_size)
> -                       __kasan_poison_vmalloc(addr + new_size,
> -                                       old_size - new_size);
> -       } else if (new_size > old_size) {
> -               old_size =3D round_down(old_size, KASAN_GRANULE_SIZE);
> -               __kasan_unpoison_vmalloc(addr + old_size,
> -                                       new_size - old_size,
> -                                       KASAN_VMALLOC_PROT_NORMAL |
> -                                       KASAN_VMALLOC_VM_ALLOC |
> -                                       KASAN_VMALLOC_KEEP_TAG);
> -       }
> -}
> -
>  #else /* CONFIG_KASAN_VMALLOC */
>
>  int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
> --
> 2.52.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZddq%3DS0H5qXZ_CLSB3Y1cNw7nY4AYTBsGRR5DmY5%2B%3DpaA%40mail.gmail.com=
.
