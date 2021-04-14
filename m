Return-Path: <kasan-dev+bncBCV5TUXXRUIBBZGT3KBQMGQEJQFOFDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id BEEEF35EF8D
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 10:37:56 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id f5-20020a2e9e850000b02900bdf2002a82sf789809ljk.21
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 01:37:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618389476; cv=pass;
        d=google.com; s=arc-20160816;
        b=CFDMrnqBe0bXP2Z9FxJ6dLC0OJBDELPz3WrlISB+HQ0mhMPYYoNUYSkEy1ZtztVO+c
         SKKDGW0O/C85EtVRcz7dokt1RiGpTjArjsqpZzxY/JYaXXq6p31oOtJTiu3imp6MNI3U
         +RRSCw4y8jEvcYXs3nsvqMlpRieRFacc7Nw+AUepTtgiLH/2sF4mIi+bJZJx6Iny5glq
         8fZEw1YhQlWfUkS8HSKyJytWy1G7SAmZHQrX4VfVxyDu0DhuGD/svZ5R0ISdgJRHI2LN
         00fuvuj46PefJOsoJcstrEloytdUPJ7rFJtmUb/zjbtcHWMHtuIgLYoMHvtFUSRdUetU
         XR6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=P7bFJ0pMwLkb6bCNhDjS/g9OyDPh2I3/xLpepaR0ARs=;
        b=vamtr7gcm2YMiFsgTN50OEL2qbwOlfBNJCix6qChn127gZ5C+CBrHrP2eUrEqJRiDH
         NcG8M7jE6AWvgP+R6Y7sgsYs6Hadvx/SvyYBCpNnCblyQWf5llup9MuglOuVYJZdeVYZ
         uNtXmkCMtKMe731GeICbe1dBLFNleImRKTvc/1OJGdPZ8I2a2t4ZTjycPtf2PDkwBBIs
         TBN60OQVJblN0XMe9gQVH+qOvUGzsiT1P1OnyyJTSqKlQpC2z07HgvG3jjyGw67tryMe
         oJjTCNiu8SI+32UQKt6/SJWMqfnrVtGMa9a2bUqeVy2cEupLXIenJW7c0YWvcHhbnFfa
         /P+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="BwF4H/P2";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=P7bFJ0pMwLkb6bCNhDjS/g9OyDPh2I3/xLpepaR0ARs=;
        b=KqYxaL7GD7vm8BSMv6QPNDuMBcnIHRPZu/3z65Eo85iD6wRVRU5o4u2ptHHsd2Z4wU
         lJmwdXQD/0cKvN6L21wBIpD9p59TYQicvOe0UL5P6nmGuWTQ69A28S5fHGcIIfQ9esbc
         d4wBdN8QDb7NcpcqqqhRo9hSU0LMJhaUWfPS2D/rs00f+VuTQJEr8hVuGL78/IVmc4tG
         twxfwF4ZWfjMbXTAUtEkJonVLIV9/bxVtYtN1KsV/38ozIe/RNOmXWbqHSwyaEv9n8eM
         aGL2EgMyG+jRcbgMCPAFTEPkKkb9W5NYsiWR0MU7Tmki0Z5rgMOM9sEgKFlNuySRj9og
         /Cmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=P7bFJ0pMwLkb6bCNhDjS/g9OyDPh2I3/xLpepaR0ARs=;
        b=Ejs+mxdfgKPWiV3AiOkSBN4PKgq8dJiQFw/U7jt2kbkURE5rcsu4K0Co/qLbRpiW/n
         zUZ34VQPzX0o0mhGaDBWJ7B1iQnVhzLgyWDdCHxUVNmzNvYh7/MJLkWHCbD1JxBm1bES
         TQ3pcTr6Ot13jSy/g3K470tt7BwdyDNXnAQzQuj+Vyfj6hxF2Z8dafXM5/lVKnkLkWpi
         hkVKFjBERJv1vRA0C4dQkAAsE+Ayyp4ESsdlB41sh/o3kOXDyaJnRFO19DQkZdddmZSv
         sWsm3eN54/XJCxjfMxlZxJlB3VuFIGnTaiRqKgQkFbV7rXBsVFf3a2cIn4ayG0U2Et+v
         AUlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Upj5OnE2JPOs9YC79O6vUU/LUYaWAWT/nc1K0dU/TDKqysUXi
	7oBOnLgDROnqftgzffegYMM=
X-Google-Smtp-Source: ABdhPJzdrgg2NvlEk3+8wsDFsFlRmgiOfGUI9S6E068Ys+gcP0ai0da4EEW6bQ3ClF4lY7c8Ac+vQw==
X-Received: by 2002:a19:b03:: with SMTP id 3mr26732182lfl.522.1618389476372;
        Wed, 14 Apr 2021 01:37:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3c10:: with SMTP id j16ls241679lja.2.gmail; Wed, 14 Apr
 2021 01:37:55 -0700 (PDT)
X-Received: by 2002:a2e:a48a:: with SMTP id h10mr9973054lji.337.1618389475375;
        Wed, 14 Apr 2021 01:37:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618389475; cv=none;
        d=google.com; s=arc-20160816;
        b=PscJrCGsZaDpQyxmZy4Q++gz2+vei6mJcoqfuvL5uTHPeEyvcqZyc8Zvw6ZXByFQkj
         je+ct9Cufai7Dvokh1kTdaPvXM51H5NVS+sjDbIjMqcxI6BL9iMX4Ds/MUu1D5qV5Nvu
         lNZKv7o4KA5rpShGmUQ3M3LrVCRyibhUnl+zHWh3+1mJwLw7Ah95G8rFowj4NOAFiXMA
         bhlsJhSH2g2gbmZaAdHRQ6o1pFYBbrx2pnCBYsuPVIr9lYdV1jsUh/Iz2N6EmQM/cWLg
         7hn21/tur6gprGUcwK+vE1TlewuledFdC4ipepJ4KW9uls1FPqZJSdC68wZ+IIKEUwZF
         KqDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HOtc4Cl5BmOPZRqmjAtE1IxvnshDfxYTlqGmfr7o1nE=;
        b=lHdPVqybKoadb4SAG/zmRfoiDEe3NPzjy4FhkIXb4FJcYIZfECJxJXc29QNkyilVig
         IQSMBosixm5uyQPB11/xOHptzTHcuNo9ExHUgj7vYt5CBMSp72cutfuTGXGLzU4JemEK
         SnfTHODVy1lE5Z5+DwoafJEUg7ef6+vtkLA+kpho0gVNFFWDn5uXi6eor5rVCTX+HFV6
         Fi4irMe7qoV9MFG4V/ea+fizi0aqHDP9418takrwhtytq4sxxVwzt7IZcR3ZUOh1dSQy
         T9V/UeOU+ivlWVFoZk6X4l/2ivgaRZLBxY5jIQLVYnEXhBpq4C29t7giyKcvoQ7nMn4H
         nX8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="BwF4H/P2";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id p5si929357lfd.4.2021.04.14.01.37.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Apr 2021 01:37:55 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lWb1w-00C0Hf-DL; Wed, 14 Apr 2021 08:37:48 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id A5236300033;
	Wed, 14 Apr 2021 10:37:46 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 60B7D203CF7DB; Wed, 14 Apr 2021 10:37:46 +0200 (CEST)
Date: Wed, 14 Apr 2021 10:37:46 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: alexander.shishkin@linux.intel.com, acme@kernel.org, mingo@redhat.com,
	jolsa@redhat.com, mark.rutland@arm.com, namhyung@kernel.org,
	tglx@linutronix.de, glider@google.com, viro@zeniv.linux.org.uk,
	arnd@arndb.de, christian@brauner.io, dvyukov@google.com,
	jannh@google.com, axboe@kernel.dk, mascasa@google.com,
	pcc@google.com, irogers@google.com, oleg@redhat.com,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org,
	x86@kernel.org, linux-kselftest@vger.kernel.org
Subject: Re: [PATCH v4 00/10] Add support for synchronous signals on perf
 events
Message-ID: <YHap2v/pQJlFVE3W@hirez.programming.kicks-ass.net>
References: <20210408103605.1676875-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210408103605.1676875-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="BwF4H/P2";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, Apr 08, 2021 at 12:35:55PM +0200, Marco Elver wrote:
> Marco Elver (9):
>   perf: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES to children
>   perf: Support only inheriting events if cloned with CLONE_THREAD
>   perf: Add support for event removal on exec
>   signal: Introduce TRAP_PERF si_code and si_perf to siginfo
>   perf: Add support for SIGTRAP on perf events
>   selftests/perf_events: Add kselftest for process-wide sigtrap handling
>   selftests/perf_events: Add kselftest for remove_on_exec

Thanks!, I've picked up the above 8 patches. Arnaldo, do you want to
carry the last 2 patches or are you fine with me taking them as well?

>   tools headers uapi: Sync tools/include/uapi/linux/perf_event.h
>   perf test: Add basic stress test for sigtrap handling

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YHap2v/pQJlFVE3W%40hirez.programming.kicks-ass.net.
