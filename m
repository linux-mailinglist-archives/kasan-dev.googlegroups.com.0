Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEEDRCQAMGQEZCGGIYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id AC10B6A9945
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 15:17:53 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id t16-20020a92c0d0000000b00319bb6f4282sf1272029ilf.20
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 06:17:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677853072; cv=pass;
        d=google.com; s=arc-20160816;
        b=Glf/8wwAHVB6UHep4DOPoz8PsqoFftZtV+I+DsP2KK4EJ4XApbgjN99kODFlKKA3Zw
         0YznhWCsVhe9SYjODTeJQ/o6unFEAb3vVuPoaGo5ZZ5/jvgcZh/KbYGekCm3Sc6bUGb2
         9ZnPFY8oY9rX2wkNJFuzsuTGR5xpdHINMUZrs65EFbAFTiTJ5PfeMB7jlb4JRHFTmtlL
         PRi5+T/Cbg1mBUGPQRaA9k/zVu05mrjaUs0j5NlJh26WwQ8QbdZ/zaxa4HQIjmRJWjG8
         JTQeH/AuXp8qvKNl9Qikyto+WboM+RMxm8GAckjr2Ds6ucrEd25cmk3tbhxn2QIJB4fX
         1PiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dXPfcMPFTg9W0QFRFUf38xIxryL4yl7yOGrkFymtxeA=;
        b=jjaOSBreRvuvFsoZ6MEMCWA+D0zT5V6nIFAhVJJZRLg0UMXyJ6JIUM/fhtvHyrkOBg
         BiXgwx8iR0Fe32DaAwcXdIcDaXi1xB4PSSAO24y5LJ67LOxlVB1UhXHf2k5rwVZHSbP2
         f80XP+RHpFG/oOgwhp/cZyvHDw9kLtSSDi+gZKS3HmdJCj4sOkCIeYvz+xXhLiEa5zaX
         DQJ7e7twirvpexO8gYlGHLrdynEcc43ZYMWo0O7aPIOUchfpm2BLgIwBbJCuKIbgZ0VX
         60RwkRSwnmCYNgbXI8Gus789RaTY+Vyo8wTGsmOQ3UjJMUgCE0cDHh3WWQpEXlkNxPiD
         4UMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hgyhk2HW;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677853072;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dXPfcMPFTg9W0QFRFUf38xIxryL4yl7yOGrkFymtxeA=;
        b=rFHKMMT+MtdbAdUlqbx4tzvfWyHhohOQwVlzRRhI9syu75IRf0x1qFSZCUu2+FkWfP
         ug7qRCJNZ08HWSWY3OZvaehOFoNfNGoAJl4Npza1mTpgzCPek8mlxhOEP1OX7q6Faf7c
         +HrViRrX3wjlAnZ7YyDVxroP2p1uVvLRzPh/I8ZVBsSWkZsNGDzijusN2AGMJv2auAV2
         agFkFW7cCqwL4eoP9yCtuTTJlzgC1fNknARdD7dwoLEQusy9SoYaaHsm5KSnd7TsHLAj
         ANxRSU3evG4mfkVTaWCpIdJ1McHnM1ZWZijLLrj6OhuvkTxZuWAbCdt5SWsABDmDeKXi
         lXYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677853072;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dXPfcMPFTg9W0QFRFUf38xIxryL4yl7yOGrkFymtxeA=;
        b=00+jXOgSf2ZRJLTgYD4VKdgLQf1oc9jFK7p/bqKPiEQYqd09rtcr37XMcYOvXy4aPl
         3v3UkTA15iRE1t7fTcWGqdBc9aN7do8j6FptOJTf81NWOhsulVlkflibOwGsl7iUS7rE
         4tBlwaP/uddvSN8CSkyCkFGJcM1DnFLz7BxQvt6uD1HD0ajQ4+E7LLZWvxR3R1EbmgiD
         9KMs97Zd8e2l6Syb8rUFwl3JZaBTz64yZiYuHDhLPSywcxp/ywfsLNaV/bsJiOVpa+0+
         CYh1hE7R0uklHDXUGDtN0S0h8vwOt4J9SizP5rAecc3lMaPdePG2Ck6nmI2/o8+6JrkD
         fj5Q==
X-Gm-Message-State: AO0yUKVUmn/rRIDhh5hGuDyowSoXGdWmL3EsAZwQXz7itK65IxbNizrK
	lY9dMwdf0EwXXWLMaPwkt10=
X-Google-Smtp-Source: AK7set8MIA9C0FdFN6GEbbRJ9t+mP72fS+/SMDSnQI2y1EtsEOQ6ALWZktQTSKOmZeIRXGGVxkES6g==
X-Received: by 2002:a6b:fd0d:0:b0:745:6b06:6736 with SMTP id c13-20020a6bfd0d000000b007456b066736mr690384ioi.1.1677853072136;
        Fri, 03 Mar 2023 06:17:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c80f:0:b0:317:97e2:9054 with SMTP id v15-20020a92c80f000000b0031797e29054ls1001934iln.4.-pod-prod-gmail;
 Fri, 03 Mar 2023 06:17:51 -0800 (PST)
X-Received: by 2002:a92:1a43:0:b0:315:537e:4b18 with SMTP id z3-20020a921a43000000b00315537e4b18mr1452607ill.32.1677853071607;
        Fri, 03 Mar 2023 06:17:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677853071; cv=none;
        d=google.com; s=arc-20160816;
        b=oUbrMqauJwYMP/J3HB3lYCnZdNIOd+VyriW8kwJV1vx9Y03UwuMCxfxNX3s4bvBZ+W
         BydI83C0I2OaUK5/Gbnczhx5OwE9Q53v9WA4J/RonpyoOojzOVU0UFi9skoCIcs9taRY
         tOIPfdoqm625N46sbzli39E7CdpgWwdloLEiL2/WCd4ck83G79XZpX9mVVhlcXHg7Ced
         8GNxINi/kK+EUvyuKwhUFE4jmA1xK9aACUWME0nXe5wMCS/wHbKEpzGA9jACgeYhH9cF
         Qt5AQNIfm2PKbw4TDY1+Eqc/WF6KVFSdK2AESxZa0gGMH/qmtVKpyB6Y7ZxCMrFpp9cD
         oO/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0B3hgicuXjM7bBAtA4QLzoXhHV0rOr+vQWIDTCOLWjA=;
        b=hNo1VEJLOIbxnZbi0xuJ8FUbQU7CLrzGn9LvqEJHFPTXBePdmObAMpj8hRDx0V440/
         D8ziSTctoyRGWalpduq4L3R6LzKXSj9YYT9BNacpW4+z7QwBGe7aTQrKIoRw/nZeRLJL
         J0d47U+tbRmA6Cje/NHBTppZ+qZ3VqX4MA7CEnGGzWfQyVt50jCKQy8+9zvdFz65ub7q
         qryjJ9gvpBi3XgrE4meWcawQldZfHm4D5sP+DCleV7FFVZReJIPB0hDeBGEJfRK127et
         iJfCKjPScujIn7rvA/7tb9tnUo4al+zjHivs+mu9ToDvJFlCMu8I4RqbqWUGQIjPzUA0
         wwew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hgyhk2HW;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id 14-20020a056e0216ce00b0031580b246e4si126780ilx.2.2023.03.03.06.17.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Mar 2023 06:17:51 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id k17so1021004iob.1
        for <kasan-dev@googlegroups.com>; Fri, 03 Mar 2023 06:17:51 -0800 (PST)
X-Received: by 2002:a02:9624:0:b0:3c8:c0dc:2d65 with SMTP id
 c33-20020a029624000000b003c8c0dc2d65mr645859jai.5.1677853071249; Fri, 03 Mar
 2023 06:17:51 -0800 (PST)
MIME-Version: 1.0
References: <20230303141433.3422671-1-glider@google.com> <20230303141433.3422671-3-glider@google.com>
In-Reply-To: <20230303141433.3422671-3-glider@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 3 Mar 2023 15:17:14 +0100
Message-ID: <CAG_fn=V4ePYQ4oYb6GXs7mOFtcuW_9HJo7BK02WK0-OvF4snxA@mail.gmail.com>
Subject: Re: [PATCH 3/4] x86: kmsan: use C versions of memset16/memset32/memset64
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, nathan@kernel.org, ndesaulniers@google.com, 
	kasan-dev@googlegroups.com, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Daniel Vetter <daniel@ffwll.ch>, Helge Deller <deller@gmx.de>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hgyhk2HW;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as
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

This is the second version of the patch. Sorry for the inconvenience.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DV4ePYQ4oYb6GXs7mOFtcuW_9HJo7BK02WK0-OvF4snxA%40mail.gmail.com.
