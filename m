Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK4NVWBAMGQEBLK5FPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B84C338A79
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 11:47:08 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id 11sf9918476ejz.20
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 02:47:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615546027; cv=pass;
        d=google.com; s=arc-20160816;
        b=h9kV3s14MJZjIBs0TdwDHpy3lgxsw+DBbx58Nss3AVSqdDz9E9hg2RGVD1JnqyPE96
         c2NEWAX+fxCvP0DYviDucGSZ0cvDA3VGGv5VkqJiHdPuwn9wHCy9YScn9EPyHcT0+fy9
         2otv997MEZkBk8LK11gl4x+juoTqDU3CM0JnIbP86MVkN0YUCPsp+6/tSSoH6Ax1cMJq
         kRakG3OpWCvQO6OKCsc/eEyf0GGKzVGUKuexPOqGzp0N2qn6zAyoQ4AE2FaVoGUAQ0We
         6qxPYMmpYJd0mNX397DmdhGMtv7Xvs2p0d+ij2ye619joZnzr0gwdIfuWT8f91bvT4g8
         a7cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=DA21iCB+Ig6Qwq1zxI46cU56nkWZAGjsQ7AFqVWZSn8=;
        b=DnbwTboQpPx2vVIUNZ3OVv6HMkGxleJu/LrRgd3gw/6Zaw0KuRXGeGVa+yTaWrZ9xN
         C6N32fcupBAa9UDcHT6J7r0/zJSkFzx6eERFFMBJqzD1787IxqGoAaOHHWaG35IMB3eY
         srRKxH6S21nlp5V6DueO5V/Js7aTKsEclfZ92+vtxBcFsSIMrbS/D2chrVF1mSbgiPgA
         lp/5UhJCJaiFcKd2PT6m6KHL7cszG9/+FJdVhI058LQev/wBNYEQn6GMpOsdjaOMxRL1
         lcH32uaBAcN6AwoHEd45WZgM4z5Ym+sfOaGnnMJER5mYwq5Q+fXUIdrQdHfyL2X+bXp5
         taSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BarfDnQL;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=DA21iCB+Ig6Qwq1zxI46cU56nkWZAGjsQ7AFqVWZSn8=;
        b=TX1yOtzTpysy//vy0Ne3ESsygfLXeZcu4qgk5/BmS+qRH6kHgY9v+b9mMnQroyKzDG
         XicGPoFtsvIIpiuH52oLYU+/iH+iEBPhwe+BGmRrQ4ucyx5IixWN/N6Joag1uDZG49sW
         dML+FTsNRyN55Qz8zBopG7ZM3QgrrfNO4fxF7eWXb4L5g2oyGvdcV3Zb1TaDxleUskut
         0eN4j4CwPUI2J7KlHcDrcHDZY0N1N3X+ryWFm3hIWcbjOmQSwhIDf2Kh3IuBN8MB8YDN
         IIVlhlYzYCRAyRXifUrA7B43NvDRpAhqmEdzgi0mRERNX6sHgVMLZID+EJ8cqNjQP+ch
         YolA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DA21iCB+Ig6Qwq1zxI46cU56nkWZAGjsQ7AFqVWZSn8=;
        b=jbb64aLsXOX0bhbi8KTJ5+3g53v24pJ5DPgMvT5aF1UBP2nEQmWnHoh5F0S/mU+E6f
         bnHsf4Fse5N58HC8VVsqrSdmh5GhOhccPgdCkJvLe6t26NQ85Lp2e+oT4ih3N83T5yYy
         QuENsSH8JUx4PkiFwUL0W+Qo8LjnDhATk3T1FFhqj2PBALkB30OCZoVgV/Z+W3YwQJDH
         VS6dmle9zQHLcJlbW6h9u4wLozzaej3Azg5EBlHRHDS1NOUN7XXJhr76N2uG5xMWBBac
         75ZPoVcOFMHyczYzp1BZuAZ+lQ0jojKP5udMSiYQvOl6MqiOOhszekNpAFHeEoJJrBLS
         nFKQ==
X-Gm-Message-State: AOAM533G7BqhZQMICxWY9hr6lXvQiz1F42t7OJ2vVlv9GM2D2zOSwsn+
	nYXML4HbFP/P5yMcIIDIiug=
X-Google-Smtp-Source: ABdhPJym9Or6fY3Jdbk1fkmI3z3dBVCcTU16WzHDVh47CMGC/TgIWZYZwrjFqR6VFi1g0FSjPMUEnA==
X-Received: by 2002:a17:906:4bce:: with SMTP id x14mr7680808ejv.383.1615546027844;
        Fri, 12 Mar 2021 02:47:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1e48:: with SMTP id i8ls1892131ejj.5.gmail; Fri, 12
 Mar 2021 02:47:06 -0800 (PST)
X-Received: by 2002:a17:907:76ed:: with SMTP id kg13mr7372099ejc.99.1615546026864;
        Fri, 12 Mar 2021 02:47:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615546026; cv=none;
        d=google.com; s=arc-20160816;
        b=zn/eN4m0S7dsxy7F+zYFGMYMktXTy8HcEbH+pOCgFA4Ho+TyZWUi/KtRvVezBS66Xg
         jc1Ag63cD+vUXHVwxT6IqgvQjx7G3Le9X3nQzB1BEd1RZomNlC7qKJbzI+2KgRkba0gb
         wuxW85dSuM/ODuV0fNPVHpea5x0JEoLYK6QlTBcd5UDqZEV1uetbfMWqfJAKwVj1/KtC
         dk793pvLXUuyU7fLjuNevuuR62QSYNQILFMuOWH/mLev3ts/VkxHCsQRnXoxXcFlcuvs
         hlFe4NcsTjwf4xBm1C5hSE7YoQRNGJgfVFPXFc8/TEbdp1ZAiEJyJfLdOwdTrLslSjyh
         1cXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5ymDbMltNO7AK4M17L49pS5zx0qn/VHAwdqQvYtor6Q=;
        b=FWXoVrH8KTa+5+vbGt5wa5NJ25Ea4iN5w9i3Hqa4cNr8KE7vMpJCUHvG+Dl1gJgfDV
         ZuR+fQp/yUvNyGGLvfd39+mtWY+kmxxOLDkaOMBm5NywunYQ69YvXtcMfnvCvoBGWltt
         ay2aQMr7S07slX+q52dzxIcM8BNChZWBu9jZyF9uZuT3numt0g2Eftd/t+2vuQuegLz4
         RCtreDTG5W8eZ12mkeiQ7ZQmV/qk3U8y6MLwE7aB/vXSv20fB2zRzX8aYuFgGqRASFK4
         cPJVOURUukDc+BWhivwk1zCObYUmDfYts++1+/tf+zuQ8eOBk9xbARTASUfsWWs3Epoi
         PS0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BarfDnQL;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id w5si184220edv.1.2021.03.12.02.47.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 02:47:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id a18so4507981wrc.13
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 02:47:06 -0800 (PST)
X-Received: by 2002:adf:b1c9:: with SMTP id r9mr13647480wra.51.1615546026490;
        Fri, 12 Mar 2021 02:47:06 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id t14sm7771955wru.64.2021.03.12.02.47.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 02:47:05 -0800 (PST)
Date: Fri, 12 Mar 2021 11:47:00 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 11/11] kasan: docs: update tests section
Message-ID: <YEtGpCV6jwWk1ZNO@elver.google.com>
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
 <f9e2d81b65dac1c51a8109f039a5adbc5798d169.1615498565.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f9e2d81b65dac1c51a8109f039a5adbc5798d169.1615498565.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BarfDnQL;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as
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

On Thu, Mar 11, 2021 at 10:37PM +0100, Andrey Konovalov wrote:
[...]
> -With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
> -a loadable module and run on any architecture that supports KASAN by loading
> -the module with insmod or modprobe. The module is called ``test_kasan``.
> +   With ``CONFIG_KUNIT`` enabled, KASAN-KUnit tests can be built as a loadable
> +   module and run by loading the `test_kasan.ko`` with ``insmod`` or

s/`test_kasan.ko``/``test_kasan.ko``/
(Missing `)

Also, "the" before test_kasan.ko is incorrect if nothing follows ("the
test_kasan.ko module" on the other hand would be fine).

> +   ``modprobe``.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEtGpCV6jwWk1ZNO%40elver.google.com.
