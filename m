Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCUYQ6CAMGQEFAGIQQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E03FB36870C
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 21:18:34 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 16-20020ac25f500000b02901ad3aeacecbsf10245592lfz.21
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 12:18:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619119114; cv=pass;
        d=google.com; s=arc-20160816;
        b=jY1FjEWzs2PPL+dVE9NGHW7b7FC1UQYEkDWTuOvVLhtgxz0iBoJlXNaOlqmdQk78vz
         yJ7eaoAHjiTphqjkar+IIsgPP+rkCDDy6QOPXrJlsI5l8bfDC556U9zheWR9azso0d6l
         qfyVT9yVIIZwYxkcp2UBPfMoyy0l2OUqm+wdHRSDTNd0SPh5bA2cg4VkPGbKXbx9cVrc
         7AZGmBbvWqCd9wIlWkXYHVw4fAZzReX7NYRkXYglzXfAq4+2D/7Nfw8rMqlZRSt8H1A6
         o4nj02WFs/HD0I9IeiF1m/ZUkOaQ+9qrGwnlmP0TbWXCb4ELfLCEEhAqDDC2gn1iHMep
         ryYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ux0MZNni/+JNwyBsRWwRoD5R1mZo1oGzKF4jlq03x9Q=;
        b=Fm8Pz2oxqf5fRba4S1HcgRWshtNg3vS1Bp+fJ9VGgq/ewDZ1RqfnceGYOsxXdoIhAH
         Ls7NqWPUZXDIN7uTdRuD+nAq6NvfodFXbkvjGNBljPCVTv5krRx8J59kkZZ9UCTc89Mn
         kRteJrIdGdZ/3rmmtjhgZlUZEg9fNCRRQnPGkcm3+ZXWESOW+JvNtgYnsAd0Aq8BjifM
         zryIdpEAY85OZ8kJc5fU9Do3Jk0B0tkybhDH2M0kAGQ0dQ2YhuSEyhVqA3pnJguD71gV
         wi0BbajGGLDbAAQAqzwnhlNTPDI4QrigYIY73DPQ6jTNKktTtw/DBYUzR5njix+qIfhB
         O5Qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="N0/i2Z5A";
       spf=pass (google.com: domain of 3cmybyaukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3CMyBYAUKCbEVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ux0MZNni/+JNwyBsRWwRoD5R1mZo1oGzKF4jlq03x9Q=;
        b=EjgmDdtty6hHVNNJDMmD/hQ4Bt8Sfhyy427kVSeBwXg7Wm/ZgqkUb5dy9Qnl4rih6O
         bUdis2xXWzj6SHB765EIzPX8AfbhgOZezJldDJYW6YFxmzm/Y6d44xQZQAgAQKqbdgU9
         TJQ/Fd8f5oTm5ieNN8ILAoll/03lCVDw1khmFYDuG2KE1ulNwOeNhlNUbjx63HsIZz6G
         IJZ/QNyDlyIhvJKw2dOGgPvvqhh1UYN7jXh4K+vxlIg461zInpaHGS0NP4Zi9SpBa2bQ
         3OCNdxNoq3qvfBIj7ijGcFMeLhtZb6aqmIkjH4iM/lLoqcn+tFzv79c5SuLfw2wmDXEV
         cjlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ux0MZNni/+JNwyBsRWwRoD5R1mZo1oGzKF4jlq03x9Q=;
        b=pRX+ASo9unbuM6wcL2twyqM+i7ehflHl52QKyMKVJrXSd1Yt07A4vHJGzc6bBw4dml
         srj3+ohfQnzaY181XYTzpCHFQC9y9fFOkQYAIcaYyHSwOyTl4tRf1YRNTSWnRuM8lbHB
         LUtlKm24OVY4Jrjbqxn+0qoCLfpD+gTP3d35eK7HPiTRqLyk0lx/26kKeDe5Ob9KZ4e4
         LPkfD/yVsOz3vXdqx2u/DN5IrwV/q1FL5Kz+FBP0ssTY4d7s5boqvKx/UdZ9Hon8GZhs
         Xkl0/eKvOQPJZSe2kxS1YngXfVyfkfEuNCyf6mYehE5cVKBOow5Q+43C+No8Kr11sUNj
         VF1g==
X-Gm-Message-State: AOAM531OTGA2zee4/slo600NsDum344vn5FOgHDCkMTjhZ5wKtz+MIiX
	dYFgmnXwlIPAfOAECwG0lk0=
X-Google-Smtp-Source: ABdhPJws2XkTDVYGTYQUJmLIajjeGsNFr8ngqeLK9Q0ZiKjoeqASryc+ao/glaYsAqFRrNTKf9yFvw==
X-Received: by 2002:a05:651c:3c1:: with SMTP id f1mr214666ljp.507.1619119114460;
        Thu, 22 Apr 2021 12:18:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:f815:: with SMTP id a21ls1316473lff.1.gmail; Thu, 22 Apr
 2021 12:18:33 -0700 (PDT)
X-Received: by 2002:a19:c141:: with SMTP id r62mr3477478lff.210.1619119113109;
        Thu, 22 Apr 2021 12:18:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619119113; cv=none;
        d=google.com; s=arc-20160816;
        b=DaOnz6wxwm/+gw4MdeuNX4NThvvlUHNmT8fpY/7dwXcYOVun1wNDyx/7Sv2pD7zNXA
         zsLjARt6RezVJGvvR2sH90QYNVfXfB4e1rCdLDT+/gvcjScWWILWsMUeZ6+LBtuvveG2
         v1VV3pu5D7DIGMk9uEbxCPbKK0CZd8BEqyUzZD8m6lp+OjxmKDy/KhJ1arlUMuJaATtZ
         ZybFySFHuWFBs2MkD2sZPKIqEYZDSV6PMWVf6+WLmanXuh+YMHa4RJseeKS80BcwgKEe
         dACD47QFyliWtaq8MReZgv7FEkg1AhaJvMPgYVN7hO8JkHP9ttss4SdA1LXjs+N2vRC5
         Uhvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Sugwskr8rXy42pZ1xDG6/Yn9grQzLU2kaW/tniDjvCM=;
        b=pxoOti8sGU797xwv0e/px4cfmcTJkM0143fB7ODbzcHjOU39khMDzOjZSsYQITXJMj
         xv6/+PSE9RYjyHixsXrBfihmVVGiC149HmRHE/R9lWqtrbXaBpn90Vp9CtryvlhtJ7Y8
         dNY4JSePqYZdGlPlxggAbevSdqKmF67EtVNo7M4cUP9C2gaorB7PHY94zHqdDfu1nld7
         grBRi4MLQyxaozKIRdpQ7cOyAKAn+YQB3RjKmjvab+4CS+KceKLflYV8ZP4/ynxWXzuG
         fbZa6jrVD42ixp5CF2wHd0n2/JOkp+rql1CgpsbBPe9pg0NDpgYC7mAU0UWOuGekRIM5
         GvZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="N0/i2Z5A";
       spf=pass (google.com: domain of 3cmybyaukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3CMyBYAUKCbEVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id w18si439075lft.10.2021.04.22.12.18.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Apr 2021 12:18:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cmybyaukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id s9-20020a5d51090000b02901028ea30da6so14133139wrt.7
        for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 12:18:33 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:145c:dc52:6539:7ac5])
 (user=elver job=sendgmr) by 2002:a1c:c246:: with SMTP id s67mr312123wmf.86.1619119112369;
 Thu, 22 Apr 2021 12:18:32 -0700 (PDT)
Date: Thu, 22 Apr 2021 21:18:23 +0200
In-Reply-To: <20210422191823.79012-1-elver@google.com>
Message-Id: <20210422191823.79012-2-elver@google.com>
Mime-Version: 1.0
References: <20210422191823.79012-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.498.g6c1eba8ee3d-goog
Subject: [PATCH tip v2 2/2] signal, perf: Add missing TRAP_PERF case in siginfo_layout()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, mingo@redhat.com, 
	tglx@linutronix.de
Cc: m.szyprowski@samsung.com, jonathanh@nvidia.com, dvyukov@google.com, 
	glider@google.com, arnd@arndb.de, christian@brauner.io, axboe@kernel.dk, 
	pcc@google.com, oleg@redhat.com, David.Laight@aculab.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="N0/i2Z5A";       spf=pass
 (google.com: domain of 3cmybyaukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3CMyBYAUKCbEVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Add the missing TRAP_PERF case in siginfo_layout() for interpreting the
layout correctly as SIL_PERF_EVENT instead of just SIL_FAULT. This
ensures the si_perf field is copied and not just the si_addr field.

This was caught and tested by running the perf_events/sigtrap_threads
kselftest as a 32-bit binary with a 64-bit kernel.

Fixes: fb6cc127e0b6 ("signal: Introduce TRAP_PERF si_code and si_perf to siginfo")
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/signal.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/kernel/signal.c b/kernel/signal.c
index 9ed81ee4ff17..b354655a0e57 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -3251,6 +3251,8 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
 			else if ((sig == SIGSEGV) && (si_code == SEGV_PKUERR))
 				layout = SIL_FAULT_PKUERR;
 #endif
+			else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
+				layout = SIL_PERF_EVENT;
 		}
 		else if (si_code <= NSIGPOLL)
 			layout = SIL_POLL;
-- 
2.31.1.498.g6c1eba8ee3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210422191823.79012-2-elver%40google.com.
