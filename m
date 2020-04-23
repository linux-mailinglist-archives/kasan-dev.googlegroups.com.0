Return-Path: <kasan-dev+bncBDQ27FVWWUFRBBXQQ32QKGQEYEHU5YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id E87C31B5FC6
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 17:45:11 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id d15sf7188600qkg.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 08:45:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587656711; cv=pass;
        d=google.com; s=arc-20160816;
        b=pj93o6dqgEe/Rtsnwfa6L+kmZEtu9dcrOmas8iWZ9QUfttHunTCFOreMYDB3si441P
         7NJpY8olK65Ec0YD4cQo5WFjOcH/dwqSt1pMsT2b2QYSpIajabhTBeW4vamtni6uPF3n
         hfnSHiRVyvTPlHQAhd+sgLCu5USbn2KqbwT1m204+EF7Ingi7ziGNtaxMAaiR92mbIUU
         X2cPKAFLSJFakzmHdRK7Kvyfb37eRjVu4ONorPYlyUshzKG8WYr8lNVoAkHhOhwPgAAJ
         WuzRwiJ9L6eun6bwgN11zCo0gYsHCRyN4e8zTnEJQ+jPcVlKrqtOcD35A445prLVBbuy
         6Scg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=KgCVw4JfaMFhHu7vZmV563EEgKCdaxHbVkA4u65DQFA=;
        b=Pfu9Z5nyjtSLXccw4E6zye8W4F49mUnBs3OKh7dMnpQPiOJkPyfTwCL6AX+iG6TNiu
         w8Q83AtcD7NYmQSCWcILT56ThToVqf4wpKD4AjsfrZ9H14Qq0dGKYamFEbLx8fhw/Tlu
         VDl7mUr6d3cBjvMDKXKZGfFKkEyrFMfIvkJBaTQfAuVFVnNUvzFUo5JRGXA2eEshTZyj
         2coZE+neQmkzs1UdKuo93SEKUUljzltvO98szelOkIKtMozzII7Wmki9pr1e9zRPVEqK
         xR3GVB8JvlcuzrxQkLn/pYMKKSaN5J2snJOXOYZ2/IVCe1jG3zxCUbGj5e4IF0+L1+FX
         3Agg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=OVK4+lyU;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KgCVw4JfaMFhHu7vZmV563EEgKCdaxHbVkA4u65DQFA=;
        b=I48ncYW8zbJXJ1memJA6KKkfiXMbvEcQH/0TpHfNxz99OnnzhjzBSI0eag45UIC3lm
         xS1MnEzgQ3V/ql+gLNV2YYGiLuRUnQ42b2HS6DLg4QRZAPc+R0duBf7N+IPXnkux6/pq
         GJCWh3qOUYca9V0fCBmhl7xd6IXg/0aYyNqVVn33gQazs4jFOPQ9kMSKD6pypPE+VJWE
         cTYsNZI0C0Ssy4Jeo5GPx0OR1xn+m5yHV/UfJ/8Vqm6MicEsowzYUXLLob759zWCnlIo
         V5AB8CDvlVa7DxToCHiF5/b4f4zJ8tM4MGyf3ATxVzimRSp2ggopCQLvvP5gMBQ3ZgXU
         Dgxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KgCVw4JfaMFhHu7vZmV563EEgKCdaxHbVkA4u65DQFA=;
        b=bWxUOkm+nJXaQy7sYzr6T0uMBoj2bQR9S+4I4tqZV4bYBTzY2M4wWuqFIKOsufNFCf
         GCjirXaIV/ic6FWwMLJ3brsK8z0iyPskmOUtkbKs49+2iMR1YvhjcS7e1a8iR2Yx6aWm
         IiwTfen62mBxK/SiD8IPe0PEa1GPUO3EU+WnaUlTbNJZCjUP6gBHOAT9mN4c3zTzqGXP
         NuPiKIB0ZsvcpCV3x2rnwhsAB6Zc42ioosWtC5RKp0MdHZjI0DjixgkHAxrev2P3CVl8
         5iayMSLLqkllsQqK5IxwTek0N3RaCKcfKoYbbuVL0usPpzXMPQnGU3tD4NL1/y23E1iv
         e4+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaE3/hHghw/Btr0QPL02JpnIfQ6HZIe06aZY9gO3Vh8Tv64Zdqk
	CvWJOB+vqNMnFDDTylg77wg=
X-Google-Smtp-Source: APiQypKnVSaDarBhzbfTrYNF7CxknEO5Ydfd0sRL6mJ7ED194uhukqJ9LNZEb9jKyghmFNJMe2o7rw==
X-Received: by 2002:a37:4c4d:: with SMTP id z74mr4199001qka.53.1587656710838;
        Thu, 23 Apr 2020 08:45:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:8a03:: with SMTP id m3ls3919186qkd.8.gmail; Thu, 23 Apr
 2020 08:45:10 -0700 (PDT)
X-Received: by 2002:a05:620a:39b:: with SMTP id q27mr4338951qkm.94.1587656710251;
        Thu, 23 Apr 2020 08:45:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587656710; cv=none;
        d=google.com; s=arc-20160816;
        b=DSEFre9Ta1QNxLAJ4IQMvq1AZPq9aY4ZGwQX8o+7pbLYqfJf0UHdWlXwlVeIfhXsU0
         Oo1WiEIz4X/2t+cFtlo9H71MaPxLuzdjBg+PhBBiRqLfk0cxQNiG9QVCh+Io8am1tyX/
         H5Bl3TVNILc10jfQoh9z+GscPXEHaIzeMdf9qm3WJiZBWGmih0wPRhD3rezcugMwlfw+
         jcMsNSvrzGadsLGwZHTFLES+jeB/xB2xHpxBig40lGKd6kFU5bX7yFQ4R13GxqMWQVk/
         WEqq0gjvGgoZhAZiFTIHguCNy3M7CiTKIzOBlcG83mXWBBiYB/KOZ1X8Q9JedNka69gE
         U4GA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=sHxljxjTpk2oBVN9jqQPNFsunhe5JYr63Xg+w6BjEk0=;
        b=lXyGp8v2jUdQK4KGN5rjZVH2oL9/CWV3raxFb74u0tScFoGKjDaZsmc2+tIPeJu/U9
         7fBUNoZV1Z/LEVwzydSbFewJeqZPjmIRxRr2S3GBkSlv9la0KRxZJuF4HuR5MK3gpJwR
         V5607dYt1FadaHNXlMZgdK2DXMztoQPjBChPP6eoI9OWO+PBkakhqt8hUhpp43VoOwC5
         2ZQa9SO8Ue7LxOxTFCB7j/yIndB3zpB9Q8Veu3cGcKKIV/HWmtxkefMWmH7tfN4XYRYk
         xh8Yshep2OrrrabaVxcer9OipnsFkr9RZXDcWtYlqs9KzvU3MEEipBILD1fzQXrLTkcN
         UMCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=OVK4+lyU;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id l23si147489qkl.0.2020.04.23.08.45.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 08:45:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id x26so3068950pgc.10
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 08:45:10 -0700 (PDT)
X-Received: by 2002:a63:7805:: with SMTP id t5mr4611238pgc.141.1587656709247;
        Thu, 23 Apr 2020 08:45:09 -0700 (PDT)
Received: from localhost (2001-44b8-111e-5c00-7979-720a-9390-aec6.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:7979:720a:9390:aec6])
        by smtp.gmail.com with ESMTPSA id u15sm2645383pjm.47.2020.04.23.08.45.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Apr 2020 08:45:08 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com
Cc: dvyukov@google.com,
	christophe.leroy@c-s.fr,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v3 0/3] Fix some incompatibilites between KASAN and FORTIFY_SOURCE
Date: Fri, 24 Apr 2020 01:45:00 +1000
Message-Id: <20200423154503.5103-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=OVK4+lyU;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

3 KASAN self-tests fail on a kernel with both KASAN and FORTIFY_SOURCE:
memchr, memcmp and strlen. I have observed this on x86 and powerpc.

When FORTIFY_SOURCE is on, a number of functions are replaced with
fortified versions, which attempt to check the sizes of the
operands. However, these functions often directly invoke __builtin_foo()
once they have performed the fortify check.

This breaks things in 2 ways:

 - the three function calls are technically dead code, and can be
   eliminated. When __builtin_ versions are used, the compiler can detect
   this.

 - Using __builtins may bypass KASAN checks if the compiler decides to
   inline it's own implementation as sequence of instructions, rather than
   emit a function call that goes out to a KASAN-instrumented
   implementation.

The patches address each reason in turn. Finally, test_memcmp used a
stack array without explicit initialisation, which can sometimes break
too, so fix that up.

v3: resend with Reviewed-bys, hopefully for inclusion in 5.8.

v2: - some cleanups, don't mess with arch code as I missed some wrinkles.
    - add stack array init (patch 3)

Daniel Axtens (3):
  kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
  string.h: fix incompatibility between FORTIFY_SOURCE and KASAN
  kasan: initialise array in kasan_memcmp test

 include/linux/string.h | 60 +++++++++++++++++++++++++++++++++---------
 lib/test_kasan.c       | 32 +++++++++++++---------
 2 files changed, 68 insertions(+), 24 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200423154503.5103-1-dja%40axtens.net.
