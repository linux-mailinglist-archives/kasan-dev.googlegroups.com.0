Return-Path: <kasan-dev+bncBCT4VV5O2QKBBPORY3EQMGQERVVYUXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id F1223CA441C
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:29:02 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-595892a393esf548152e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:29:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764862142; cv=pass;
        d=google.com; s=arc-20240605;
        b=S7NAEBlSfqbiPMaUdb00L4tQbeRJFkiakkA99WQa7v1qtKvG5v53Uv1qhJK0Fq5IKq
         yW5fKL3smSHw8cxxtOoMrBGD+291nhppA7+aVU8wyRLg1Sb0DupdjqsfHhmaioy9k+nt
         7LbAuRbrqPnt4gpuntChSwuvZ8JpYaSn56hkIVLSQmxWojmhJx+28YJF0WtHkTqbR+IR
         Dbi6rE8/TiMrIdAGjJwXbnUB2ssHZ2+eyWenGOnv78ZzVW9pSbOpfZx2IEauzXBmPLj9
         hhn7bKiVwSzjLqpD+KbhXI88o/n0nDWwy91y/pbh+rNLiWy4NG+E+rHPei9JTPnmR1uO
         6iDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=dnJc2Kw8vJ8sM13vVhidBPXmalXC60saebDfRFKUw8U=;
        fh=7VKtE8pPL4/1eZLbBJXji3XxgQShKfU/YcDMUvtltyk=;
        b=I1cUlgFR2AOLK5ydWwP7wFtfXFnFMtGBHbvRU1tQYi2DZpBBaqdNEW6DH2wiWDnnNg
         bdnYF1LCmLCM0uQ/hyljo17J1nhKJJ98iT/Uk1+wxb6CCHS6aPJZyMg1JCdRoYhJxu35
         rZj2EycObpS7rlGZhaCjhwH4/fDMpHGsatoEufF6BI/6MXZY+6AedwpY8FQeaTqnw3Qk
         SOoWZCl5mGgShYDY+sy+3tjXh1bP9T7bafwexQ55gOTNeihtkjzqNOPCygiLJUdSJMwq
         l1PEMiBgbSuuLUCGXwiwqnG/uaZ1k95Bg8yOgjPPCYg5meHVhah2dL2B5OLFgds5vv92
         3bfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GBYV5sPJ;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764862142; x=1765466942; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dnJc2Kw8vJ8sM13vVhidBPXmalXC60saebDfRFKUw8U=;
        b=lZRUUi0y1PhJmu9hSf1iivUm0xVvEpY+Hzt742DR3fXcA/elNWUSzU5uGBjurkcAiG
         Yw4gVCiITARnbBOmWyDw0BgzRkbNPkHp89dvWeISwtxSR83EnohjtU2Q2ifkKP8GyOGk
         qXUSdc9Akiw6DZ74DTabBVbf4VaoN+LPEw4CoeIWp9foEdwwN9MaSuZwD64J+J+2iUJD
         gWHgW7LYkM9PNk5xPWtK4RBSPAYLnwg1+TdDlobwokNH/4q94AxSKZCdB8qtUzb8MMJr
         Nkt5hgqm/535VMa2ia9x0srj5uJ+R2Bw3TGJfjii+VQv8CRg4JeGwM8XX7rrGEedWYc0
         V74w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764862142; x=1765466942; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dnJc2Kw8vJ8sM13vVhidBPXmalXC60saebDfRFKUw8U=;
        b=agYvAxXkD5dOUwnr5NEJaDyab1QQPAOsAvrJtMQE4ipj01mV64XuPug1hdigJHfK8x
         9jCOa1jI9dJj2cedZ6Mz26flcZl86KZZeEBNHKYRfGKkN3Mr/tbiyOAYoosG5BBQFcyC
         UHFoxk3zAmQmxa0BNdk/iAVXpboq1rSNIsnBZToocOK8Ck9riUCYFFd+oArNmy/Vwm3C
         cL7meI3QA6EwojhqJ46GImf8tWmPjnquUGFefDB3qWZ1eL8d+wMWC1NPXsQA4oqhB9VJ
         ZRXXtivyXcit/4ymbF2vYZxe5uuP7viICdQtzFJYQrQ/b5M0pjDN9S9n09sellV6ut1u
         mtAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764862142; x=1765466942;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dnJc2Kw8vJ8sM13vVhidBPXmalXC60saebDfRFKUw8U=;
        b=XTa8YKTh5XOTwt9fNkPypLAcjDxRVQwW3s6cJuw6SMd1OoD/M82CKAO1DfsnfgZofX
         oaODwmf/MWI9vxZo+jq0fqNNnCSoc8Wwjf0segzHPR/IqDYWICZzs68ygme6E7FUHlTH
         DIz6ius+3Hhs3dxe5IXkWeeEz3FCXF8rXU0wIjhqDIQqLmXSkoviJpuikrDKtr2BztPi
         Pdw8KUmrGEYk1x301FMQ3A7QuJ1NbIwVy7lVLxJ6HAxXZaQjdCfiq5wnFOOPzR0eYGBx
         4D4gGO7FjAuMZwz14QN/y3TMYZctqelF6f+oEoewB5G4YDGsQ6erg1+usPBUTredtohf
         m6yA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV/XYrKYZPHJqc6Br4PwgnoyU1Jc7Ggi57mEpj+YHxksFRTNcW7OH7CUNfS2LCmirbxDThsZw==@lfdr.de
X-Gm-Message-State: AOJu0Yzb5gnT/tXIFZP/SPqogut/440uLoN8E+WJlmKLXrTrSPcJeoZF
	krQZSzFCKFl8g05VuX/h9SFimI/8ZKOpFiUxWBE8YWH/OdGv+qq/B16Y
X-Google-Smtp-Source: AGHT+IFmSbWwoYnYfzIyD39/YA53QRKR1qRTZyW5bA63yU1dBuKlNyQz/UQo4i04y0tcpdP4bAM4ZQ==
X-Received: by 2002:a05:6512:3d94:b0:594:5545:b743 with SMTP id 2adb3069b0e04-597d3fa063dmr2608533e87.27.1764862141828;
        Thu, 04 Dec 2025 07:29:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZvCzri+NG1gQSSz0Y216AkrjUCxuH+OVMgefpd4rMp9w=="
Received: by 2002:ac2:4bc6:0:b0:597:d7e5:78d8 with SMTP id 2adb3069b0e04-597d7e57f57ls186284e87.0.-pod-prod-03-eu;
 Thu, 04 Dec 2025 07:28:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW6qPcWgjlD4eEZS3iZk/SbiMdjgVyLNaz3/j+3qzObe/T3oUYPudzeC+G/ySoqLd3wgOsuxBr3+lg=@googlegroups.com
X-Received: by 2002:a05:6512:b27:b0:594:2cfe:368f with SMTP id 2adb3069b0e04-597d3f0236cmr2969179e87.11.1764862138484;
        Thu, 04 Dec 2025 07:28:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764862138; cv=none;
        d=google.com; s=arc-20240605;
        b=AFLoLFAsUsMEOamRbfIzGhCN5bVE3RtSL5fM9z+X8L8mY8pmMt93LzVJbXa2e7vfr4
         LNXvHcUNaRYktAXc5gs8B9gNQ2X4wES1oUmQRz6J45dRTfWaCWnhpzG1lt9WZKiHgwTd
         kzJAkvmImwE03TSVhuihB0F046s3f9WAEDTW84suz49BojaqHu8SSrtQ6yWn7caxxTdy
         umJ0i3C1PzuOUnThVedv3b79/fQkmr0OXs0UzCv4dxUt7v+2y8xsxjIUlpLq29v55o/8
         VEtliMISDPDXt+evp7AG6XyZvOhivcKgrpNctN+PEGCclPO9nDYXVuBPjt+V1Yh6jvdG
         Bwag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1MI5aTy+R1SqmI1yzGL1uAuu8o2FFOs1gD1ZnAhB164=;
        fh=dlXlyOudQZ9yIW5NmYJf636x/Tazt+NjXvWr1UB9N08=;
        b=d0eA+B+nSSjjZwjY2jIJdqGAnYMAj0kEQcctHivf52BLWfyxSP013BH2xDnIWFJPWp
         7ZDdNzhAY1gmclHFVKQLZrvrEN/I7GDJCqXdCWaKkEyHJS/ZKSM4Oviwm9JLxhr3WMpH
         GYWTrB3nA/CPvj5ZMFoeP0iYppW+xNiC4vqzT4fP7hPXKpL0pzk9XG293YJb9yYrp1Zr
         HlSgkWo17gH5FKPmWxmT5j60Ym5/6f9aRUi/sz42kfy5eh5LsvnRthxqFqPEnbF2ML4S
         0y6Mz+zfWD+o9jjmTWfIJF1UDXjHh/OP/fWDYgqKY9uv6TCf3tN7dY1RqTxAVuZ7EnDn
         rreA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GBYV5sPJ;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37e700c2581si327141fa.5.2025.12.04.07.28.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 07:28:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id a640c23a62f3a-b736d883ac4so183216566b.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 07:28:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW+U83JL7+K7X3TiZa4IuM+HXkBTAW3rPXuwliuPJtb4PBp+heJAX3AYfqXBGGZDiwLncLUKibBmhQ=@googlegroups.com
X-Gm-Gg: ASbGncu2ZX9Y/mXUwvfR0cK+8KBJG5RZXfPd+bW0N89vsDh8KWpZYAU15SbAvgrNv7R
	7+AvfB/1+DXpeS73p9PE/E6AetA8RBgbeCDEhmNz5+ht8pPo/9Gmgq4pMpx3/bgIq3sKaERuuX0
	W2rhLTstSIU4gojdyxo/RPn90ORuo8N3HZhmWN0dgwCODm4reQ5gmx8vlv0uE1ISeUm9+N2a7bs
	i4/9OdlGuFqCAkoSsWCZzVgkGoxoCg7LFCogubQ8bKmSvF+7QJJCLsejB4ytCgCjQnLJt51D+vZ
	r+Re8nZ5WY94O6NbuqJpqYYY07fkgMkW+rj8XazfBsVBwkFpRL5lkamchHlyKtrFjA105QJcvMv
	VsviRjw==
X-Received: by 2002:a17:907:7b85:b0:b73:8792:c3ca with SMTP id
 a640c23a62f3a-b79dc51af8cmr691284766b.32.1764862137818; Thu, 04 Dec 2025
 07:28:57 -0800 (PST)
MIME-Version: 1.0
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
 <20251204141250.21114-10-ethan.w.s.graham@gmail.com> <CAHp75VfSkDvWVqi+W2iLJZhfe9+ZqSvTEN7Lh-JQbyKjPO6p_A@mail.gmail.com>
In-Reply-To: <CAHp75VfSkDvWVqi+W2iLJZhfe9+ZqSvTEN7Lh-JQbyKjPO6p_A@mail.gmail.com>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Thu, 4 Dec 2025 17:28:21 +0200
X-Gm-Features: AWmQ_bneRNOGjAW4jDt5halz319V6V9HvLuc9jLOtFFaLshPIC4KOutQs5--etw
Message-ID: <CAHp75VfgETRHgGkJdVezraFDogtB-KQT1UDWn2RyWeNZ6hCU=A@mail.gmail.com>
Subject: Re: [PATCH 09/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: glider@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	sj@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GBYV5sPJ;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
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

On Thu, Dec 4, 2025 at 5:26=E2=80=AFPM Andy Shevchenko
<andy.shevchenko@gmail.com> wrote:
> On Thu, Dec 4, 2025 at 4:13=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gma=
il.com> wrote:

> > From: Ethan Graham <ethangraham@google.com>

OK, this bounces. Please update the series to make sure you have no
dead addresses in it.

--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AHp75VfgETRHgGkJdVezraFDogtB-KQT1UDWn2RyWeNZ6hCU%3DA%40mail.gmail.com.
