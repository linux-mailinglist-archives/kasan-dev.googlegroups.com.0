Return-Path: <kasan-dev+bncBD2NJ5WGSUOBB7NL7PCQMGQEOF6CM4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AA8FB48ED8
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:11:27 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3df9f185c7csf3247108f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:11:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757337087; cv=pass;
        d=google.com; s=arc-20240605;
        b=HwryBvlfV7ZO46kqKsB4sVHUvfIGIYP6ER9y/1quy4RCW40rTNlg5RzZ/+Gltajvc1
         DtF0xHJ4Xdn5eEb0RuHXNZoJq6X7GKGMxwScD0IF9PS1zO+/834Za5bDHO8Z+KKpvrjU
         18bCv5CUmdF5y4jovO+V5aMcuHsM94PKeUuKzOJ9uE64AbFacAidRmeh7BI1981C9A5B
         KJfBcj7jsJuMdty786bFUzhgUm6Je92b5XAjAQOx1N7NYsgpymIDKBJqLih1QJt9HRM4
         +HmfbQHyDSaXQUoFGQpbK+dpnllNeH02cM4bvoW2y016vDqGEBFckuPXQRmyZcfCbJVn
         l8Xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=8vljhb+N/bBoEEJN/iNycU5mJK8iERKSvHEOU5FiBe0=;
        fh=jS7ld1i9RCX++01Hh4PMl43bImqR33FcBbTS2V4ayxE=;
        b=RvLWqbMwS0SdhlcyipdlLDvpHKQB7oTnm+W66RQBiO7nzesOF58apOp++7zwP+dWQD
         LfCk6a+lpWxUPa4n0t9yF6cm9rlGyGtoeV6FlIXVRH2cfTeWBE9dY7N4jaoLFPRU8AMV
         ytjEoMaFVKSGv5o0HQc5TqEvgPXDpFzouvdLXIu5rIRigiRhXhvz4cQiZ3PaXYH6s4ER
         LUtn498sfB66fE9D5dr8k7vC+A+N3MMlhdrMDqa2UOacs/C8+uYUTKBGkR1h/tliIQ34
         j3jGkgZYTMN61ml+uoRy881ZgZL2o+EG7GgjFtmlB3ApQxQSEyEmKmEVmPCoNR+mTaXv
         M3IA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=AHaB+0w3;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757337087; x=1757941887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8vljhb+N/bBoEEJN/iNycU5mJK8iERKSvHEOU5FiBe0=;
        b=dRcfzglqKvoe8y16u0JU1fjHv6wKBDSBxniwz5AtYVBiFEpIgyQFGQzWKFTmw1olAC
         fMEDENq28mncJqiyOIvy6KSeoXQfD0RKtiyoApTtdgakhNTZamt5tcsdYKVMlpUBQgJV
         NXGNLUF1BOlvXLy4CebJy9PvubkbtmKZaC77zX/rqIOVD5uh0QLEcX7JAY9JusMI7hsB
         QgFumT7DDwOFGSp92swTUW9k37Vq1szd1MWV9Y73p34TEPCWcZ88xkbSLcO9xrQnbeFy
         mZ7ce7Bo4tY1TF8Iodriu580BeVVrnS98nU7OnZ/Nst9bqmpZrJ2JoZFwaERNY7mITjV
         bL7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757337087; x=1757941887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=8vljhb+N/bBoEEJN/iNycU5mJK8iERKSvHEOU5FiBe0=;
        b=g/tmJ7y71VBTMtkPpRHyHeNd+JzBBjS43rByMazGv1p3oPO4y5X0qtDRkprPzEQQBp
         gSyuLo/JNCTPlX2f0cDQCFrS3Pj+omTGo5JOEA4x+QMfTEbdkhTbfRQhJqy9SvXAANEc
         7iT7uwuVJAIL+yGpE/CbXvK1ZU5mP3FV/yjGdZFerhqkB+0gQm0HBUhNfRhvYYwuLJUq
         xdCwJNQsUADOq1Wmy8EazMWdbEoOVjbMepIk3yN3+jM5oSRQ9jSqXUkOkLov2cjhP2nj
         TGhX4mWQ5fBHeb0HfHK/nH4NoOUutnqbwof40aLtGSnnBCalespQFksCkfHtL1cMYiyb
         ryWQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWWDQ4iha5u7g2p6akp/IuLNULfzgK1/RxfnMQVwbRP1vmsRDNCLnJfgoE4loBHcuSJDRrykA==@lfdr.de
X-Gm-Message-State: AOJu0YzS3AYe7XKgHcDbMiCtaQUtUpRDHO0qCKp38rSCYRM+ya0jzBna
	dsylQcJqoMROu42rYW2hOwr0z38dFJfTVL/rO9bhzMuqcn0jd5rCejwb
X-Google-Smtp-Source: AGHT+IFt0a+NWUB7coAPxVH65SAnurUxl4zPCgrpb+VMwii2mhRwXUFVQSzf2lp/k7ODmB0mM2PY2w==
X-Received: by 2002:a05:6000:230e:b0:3cd:6cd:8c2 with SMTP id ffacd0b85a97d-3e64c69424amr5812283f8f.60.1757337086340;
        Mon, 08 Sep 2025 06:11:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6F8dk8ydD/+8Bijd9R02lUiu491X/Zem7WlapmxSaawQ==
Received: by 2002:a05:6000:4282:b0:3dc:f2f:ee3f with SMTP id
 ffacd0b85a97d-3e3b6091636ls2154598f8f.2.-pod-prod-07-eu; Mon, 08 Sep 2025
 06:11:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVKxibsOxjEBqBq0HUBZQZgHk8uGtpcI1knruAirPaFWGJm0V4NJu9JgCtqpwUujXPXbuMaJ8vg22k=@googlegroups.com
X-Received: by 2002:a05:6000:24c6:b0:3cb:cc6f:734e with SMTP id ffacd0b85a97d-3e641a5fe43mr5828195f8f.14.1757337083620;
        Mon, 08 Sep 2025 06:11:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757337083; cv=none;
        d=google.com; s=arc-20240605;
        b=fYlRtlLaeNNhkq49gHHwQ1/7u+swmBRtoEK2DSMmn2blUinD7W79//nbAPO4PHZPQK
         zOtkhLo5ndOKgvZVFhUzUfVu1AQcM/H4U2VHRAeF/bqXo9qeWM3k+HZgEfR7FYRX+WfE
         JYWmY/orslhlZrLwoTio0YnBzAOkNAor+7PO3DvWaJoeWS4O+yhxD+8PY4wTdrAFYAoR
         OGAw/+Y90u+iAa8fimJz0uc52MVpAWjY0NeP3jNXxZs2G8G18qDW/Lgl1X2S9A93a/rB
         EiVlenC1TWhJMt2+8T1jkzL3OVx4bRIXBwe2eNFZEM286LYI/0nrVU4bZBdav2JmrO1C
         kdcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=NkcpqsNtIfH0/2T4tzf3ihFLKwziOQ6MGxZZ1TVH8gc=;
        fh=B4zQkKl/mglS6F+WviD/XvqFqF628KNNuctMB71Krbs=;
        b=GTsAVXML78nuE963S0YghGHySjFPc8i0q+FvHzCo+UylC8hHayMDtxBAYJvB3n/Btj
         rtP0s0iZcX7m1htvmJ+0dqYz6ZVGGh+qx7Oyun024lomZovuFPm7yYfbZx7D5Ujr4Wcy
         /uiDYxt96CT7zjS/tgjnH2j/lwXgq0Tvq+W3CiBvM92jFTemSS4LB1BKQgKCDMgjvi4W
         UT/2K1VoU8vcbBORZ0GifZIBeeiuhNlYyY8Cp+oodFaym+mHTf9DW8w5pTm9OsG//NnT
         QinFZ7lRRH1XORS+BpQLleUZ3yz0LVRGE1hM7iaA3We+vafXR8ezyk0kRJIbuhFJnkeK
         FFwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=AHaB+0w3;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3e54de253e0si137533f8f.1.2025.09.08.06.11.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 06:11:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98.2)
	(envelope-from <johannes@sipsolutions.net>)
	id 1uvbeH-00000007aGR-1hXH;
	Mon, 08 Sep 2025 15:11:09 +0200
Message-ID: <513c854db04a727a20ad1fb01423497b3428eea6.camel@sipsolutions.net>
Subject: Re: [PATCH v2 RFC 0/7] KFuzzTest: a new kernel fuzzing framework
From: Johannes Berg <johannes@sipsolutions.net>
To: Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com, 
	glider@google.com
Cc: andreyknvl@gmail.com, brendan.higgins@linux.dev, davidgow@google.com, 
	dvyukov@google.com, jannh@google.com, elver@google.com, rmoar@google.com, 
	shuah@kernel.org, tarasmadan@google.com, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, 	dhowells@redhat.com, lukas@wunner.de,
 ignat@cloudflare.com, 	herbert@gondor.apana.org.au, davem@davemloft.net,
 linux-crypto@vger.kernel.org
Date: Mon, 08 Sep 2025 15:11:08 +0200
In-Reply-To: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.2 (3.56.2-2.fc42)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=AHaB+0w3;       spf=pass
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

Since I'm looking at some WiFi fuzzing just now ...

> The primary motivation for KFuzzTest is to simplify the fuzzing of
> low-level, relatively stateless functions (e.g., data parsers, format
> converters)

Could you clarify what you mean by "relatively" here? It seems to me
that if you let this fuzz say something like
cfg80211_inform_bss_frame_data(), which parses a frame and registers it
in the global scan list, you might quickly run into the 1000 limit of
the list, etc. since these functions are not stateless. OTOH, it's
obviously possible to just receive a lot of such frames over the air
even, or over simulated air like in syzbot today already.

> This RFC continues to seek feedback on the overall design of KFuzzTest
> and the minor changes made in V2. We are particularly interested in
> comments on:
> - The ergonomics of the API for defining fuzz targets.
> - The overall workflow and usability for a developer adding and running
>   a new in-kernel fuzz target.
> - The high-level architecture.

As far as the architecture is concerned, I'm reading this is built
around syzkaller (like) architecture, in that the fuzzer lives in the
fuzzed kernel's userspace, right?

> We would like to thank David Gow for his detailed feedback regarding the
> potential integration with KUnit. The v1 discussion highlighted three
> potential paths: making KFuzzTests a special case of KUnit tests, sharing
> implementation details in a common library, or keeping the frameworks
> separate while ensuring API familiarity.
> 
> Following a productive conversation with David, we are moving forward
> with the third option for now. While tighter integration is an
> attractive long-term goal, we believe the most practical first step is
> to establish KFuzzTest as a valuable, standalone framework.

I have been wondering about this from another perspective - with kunit
often running in ARCH=um, and there the kernel being "just" a userspace
process, we should be able to do a "classic" afl-style fork approach to
fuzzing. That way, state doesn't really (have to) matter at all. This is
of course both an advantage (reproducing any issue found is just the
right test with a single input) and disadvantage (the fuzzer won't
modify state first and then find an issue on a later round.)

I was just looking at what external state (such as the physical memory
mapped) UML has and that would need to be disentangled, and it's not
_that_ much if we can have specific configurations, and maybe mostly
shut down the userspace that's running inside UML (and/or have kunit
execute before init/pid 1 when builtin.)

Did you consider such a model at all, and have specific reasons for not
going in this direction, or simply didn't consider because you're coming
from the syzkaller side anyway?

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/513c854db04a727a20ad1fb01423497b3428eea6.camel%40sipsolutions.net.
