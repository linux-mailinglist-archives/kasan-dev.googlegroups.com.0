Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBE44T3FQMGQEY5FDX4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 672E0D1ECE4
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 13:37:40 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-64cfe5a2147sf13500277a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 04:37:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768394260; cv=pass;
        d=google.com; s=arc-20240605;
        b=E7XY4rPg7ajBKk15ZI9VEhjJw4P4+krOuZ087zPvOfeiZhLGbyAycUiHu1Xm+OeoLr
         8Z24KE1VhdqxttvZzJFojKnA+9BGtSAf+tFLXDqLSlMF3ufgZMXWjxq4R6FdoGoGjCKS
         s7Z1riZ9OEJNBsP0twEApiW8EzXxzSB6VGGIvi5rtQLIiymUYSJXcDwBtnzx9ldDXOHx
         5skt7h0U5dAmO2T/Q1hNeZjTMvH380ScfFnnQCSOPFpH95E1JXKCze3c0YvRF09bjbSo
         fo0hvsF1uaVA0UkjNv4WBx+KnKX+vX+NTPyBArGdZk+3659knjKHnb8OFWWpE4H/jVrv
         ObWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=si1RXXvXR4tGYE9NEHXOSr7LImuSav3G+kjOdVLePjQ=;
        fh=7nxmpq/7UA+JreGprahknGv8c1KgqkjtXCvFWX+ZhaQ=;
        b=UYo/5dWyd+DfXR9FiHDmfDaSDOrh25XWrdHSWw9ruorlCjXFD7RryTWobUdHFxYQ6w
         D2xZg+kiAw+dXcKQM3EHImcI5jTPZ6+4iPoD54QPoA3h16Tcd9KaAWnYltr9/TFE7/WB
         jKxz/EJBvxH8vzJt9iGTwVSaTlg0tOTmdR77aNOiEBPcFGbfVGpBIEnNZm504Xumv21E
         p2wsozeAU80DONDJGOB4tJ4Q3S0gdYCEE8JNEc4U4QmO2SV4gdZ+PHudbvPsqkJmuymu
         gMw7dBY2qVQI+bqqaB7rXd4VNORWTPmfOaFqwVzsfpJ2oZQ3iJwV7X0JCYX+a8uBXG6P
         SXzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=hvqmi7d7;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768394260; x=1768999060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=si1RXXvXR4tGYE9NEHXOSr7LImuSav3G+kjOdVLePjQ=;
        b=Z3iGT1kFtpgiysuw8wsldGy0rOXzlx57dlHJDN3dtEdJJ43ULZA6TTUPv8Tf7+Cgdn
         9A2dDiq77mS7uGFlylwZuxKdQB8ZebY7WjmvkuqvAqBAfwIsHO1QzeaQiLOldzyC79o5
         SK9LrBsZUZRIPrEE3RkdC4TP5x+Of2P/l0+CLyd6dl8lzGjK9U5ftHWXVfjtH+w7WVGw
         s/AckKBfGZoUPZLk8nF0H8AZ1sBiUo7+dLgic8iIIIbtqhUqZX69g1BgcNhNECRY7snR
         32+GQdeD0X+h0OV+l+P2vsX1/h3vSEEfpyDMAbZSfjNdHkclX8XMcy6dFrRA2dNumZVh
         m1xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768394260; x=1768999060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=si1RXXvXR4tGYE9NEHXOSr7LImuSav3G+kjOdVLePjQ=;
        b=AyJ4tM5mNNP36O/pfuvzmM34ZebgRe5XtkrhgsnUiWDH68vLqfDQ8obAec+7KiQuhH
         4B9ToTXTSO1ePrV/bkdTXqy+FuiX1Kzoas+wa7fys+oR24EyFnMzkG0U6RD6i8SUpC3T
         HQCpcjcElxi6nGrJUczdiZM9OI2HWCgaIQ0h1DJtZeM7vwY+OaS3qfG4hwM2WVnLqR/4
         gB5KWJ13gzfDJdo5HPqhwmhKwywa7euTLN/13mglOrjyLZ061Kog4S0Ez8Y3ybU+CdNQ
         DpMWwNaZ9XdGCYJUybBdr4yZGFi/E3pinp3mf+c454FYYjC0VYNMUHfjSlJxIjdVp+K+
         7vfA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXcx4Jzh0sDV3l/2NGx4v+vwzHnf4Za95RzIAg5W/+P2sMZ7KyNjG0T11L8PZd88ryfQsUKTA==@lfdr.de
X-Gm-Message-State: AOJu0YwzF/wYEhX7DOn7u6W8fcyaNJEpuBCDKZto6c0xR0dikd7GDvVy
	yppgDUOMEdH2iKWcUdC2Lr5CmSwqsjZIZRu207KWFueU9+vAvVh1A5ZS
X-Received: by 2002:a05:6402:3492:b0:64d:2822:cf68 with SMTP id 4fb4d7f45d1cf-653ec44ad5bmr1843155a12.21.1768394259607;
        Wed, 14 Jan 2026 04:37:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HX1ljDCgidBrAY0TCCT++8rKzluuPTb0ObAsXTDUm5Dw=="
Received: by 2002:aa7:de15:0:b0:644:fc33:37b6 with SMTP id 4fb4d7f45d1cf-65074900007ls9398728a12.1.-pod-prod-08-eu;
 Wed, 14 Jan 2026 04:37:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX80bltoZRpHEc0UJ6YnQa/EWBi7TaCvjTjFxxSSxMaqTlDhY6Ge/wnDxV8rXuEakUjgXg1NOKkBgc=@googlegroups.com
X-Received: by 2002:a17:907:3c90:b0:b87:3809:6982 with SMTP id a640c23a62f3a-b87612daed9mr227028066b.57.1768394257177;
        Wed, 14 Jan 2026 04:37:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768394257; cv=none;
        d=google.com; s=arc-20240605;
        b=IZd1lURd21Eo6czfl0elJVNFGXQD6KmiDcwRROFsPJAHCWo9cgWm1qADE2xzZ3cPcV
         +oW+MyhrAJWi5qeNYQzQxRWlMQq7uhs0+bJK0V86ou82VnNcilyCYcJiq4QChJhkhR/3
         FpVnEGg9h2vH9tjCW0QJO1Y1lwQ2ZCwFUoc3ysoWPr/j+rg1zxRCb5y5pY1waYIFwOlY
         xNHDHTukjQcy0OHQ4jqucoFp0vt37C/TnngjjTVnaUQdmMQWV8qBOltE68fcNMAbYzFw
         Zr4h3cYXTleoeF8xRwW0x3ABXj/SJ5BCdstIimXD8Wc5f4c8wZ+E8XZc5ZYpWLZ6yj6k
         aVtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=ivImLx0IMwWptsei2EtrkPEC8sK7x+WsxIR0q4hvYGs=;
        fh=3Nj/6S7DE791Ov/IphzOcOkqPMoFMhU71B0S18FPhC4=;
        b=TMHg1/djoci/GNTBpMCGAdZEwq0/Cxpj4tq9kVrNOStjmSsGLz7I1tVWauzqpJJ0wL
         wfWhHSYBo4pQoao+XTd/aP5iSyIf4I+CB/3ikrJUc2QZRv6fhrqJRcT1twZVReRvR35B
         Yza/SzJNzgiqxpeOrrdt79+cyJD+Jb3L9CJbV9OHA0Axy/iPBxdnfRZNnp03cGC+JbiF
         /WVCuDTbITr7lT27KeJXhXJ3yKBK8faIR7rqCHVnTsJ2qd3YPbyvreX6vzZeaq551oqv
         RQ4HfXXGutq37LEcovvzZTWRA32j5YDNnf4rHZF3zzP0l3fAOxc+t9r2tAM9UbpY6ZuU
         aegg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=hvqmi7d7;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b870059843csi20805266b.1.2026.01.14.04.37.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Jan 2026 04:37:37 -0800 (PST)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98.2)
	(envelope-from <johannes@sipsolutions.net>)
	id 1vg07s-0000000Be2H-0lg3;
	Wed, 14 Jan 2026 13:37:28 +0100
Message-ID: <27c35b1f39c4cfaaf3b8322bbeb793c268fe4b6e.camel@sipsolutions.net>
Subject: Re: [PATCH v4 0/6] KFuzzTest: a new kernel fuzzing framework
From: Johannes Berg <johannes@sipsolutions.net>
To: Ethan Graham <ethan.w.s.graham@gmail.com>, glider@google.com
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, andy@kernel.org, 
	andy.shevchenko@gmail.com, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com,
 dvyukov@google.com, 	ebiggers@kernel.org, elver@google.com,
 gregkh@linuxfoundation.org, 	herbert@gondor.apana.org.au,
 ignat@cloudflare.com, jack@suse.cz, jannh@google.com, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, 	lukas@wunner.de, mcgrof@kernel.org, shuah@kernel.org,
 sj@kernel.org, 	skhan@linuxfoundation.org, tarasmadan@google.com,
 wentaoz5@illinois.edu, 	raemoar63@gmail.com
Date: Wed, 14 Jan 2026 13:37:26 +0100
In-Reply-To: <CANgxf6yGDGAD9VCqZyqJ8__dqHOk-ywfSdhXL5qATfxnT-QGFA@mail.gmail.com> (sfid-20260114_132852_914833_479AECE9)
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
	 <CANgxf6yGDGAD9VCqZyqJ8__dqHOk-ywfSdhXL5qATfxnT-QGFA@mail.gmail.com>
	 (sfid-20260114_132852_914833_479AECE9)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.2 (3.56.2-2.fc42)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=hvqmi7d7;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

Hi Ethan,

> I wanted to check if this v4 aligns with your previous feedback regarding
> the tight coupling with userspace tools.
> 
> The custom serialization has been removed entirely along with the bridge
> tool. This series now focuses exclusively on passing raw binary inputs
> via debugfs with the FUZZ_TEST_SIMPLE macro.
> 
> The decoupling eliminates any dependency on syzkaller and should help
> remove some of the blockers that you previously encountered when
> considering integration with other fuzzing engines.
> 
> Does this simplified design look closer to what you need?

Thanks for reaching out!

We're doing some changes here and I also need to focus on some WiFi
features, so I don't really know when (if?) I'll continue working on
this, but yes, this definitely aligns much better with what I had in
mind.

FWIW, maybe for new people on the thread, last time I was considering
building ARCH=um in a way that it would run into a (selectable) fuzz
test, fork, and then feed it fuzzer input coming from honggfuzz [1]. I'm
handwaving a bit [2], but this would basically bypass userspace
completely and let us fuzz any of the tests in the kernel with "reset"
for each fuzzing round.

[1] selected because it's compatible with what the kernel does now with
kcov for coverage feedback, afl++ currently cannot deal with this for
some reason

[2] because I hadn't quite figured out how to make UML a single thread
only and get rid of the userspace running inside of it


Regardless, definitely yes, I think the design is much simpler and even
if I don't end up integrating honggfuzz this specific way, I do believe
it will make it much simpler (and more performant) to integrate with
other fuzzers.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/27c35b1f39c4cfaaf3b8322bbeb793c268fe4b6e.camel%40sipsolutions.net.
