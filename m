Return-Path: <kasan-dev+bncBAABBMVTY7EQMGQEM5HQEMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D6D70CA5040
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 19:57:55 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-5957bd7530asf1263603e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 10:57:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764874675; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zt8VhcGCCaVkXmHMtOEMPrem73CSP9nKd4gGLySNtF8y1Ed+LSFyOK6LuPDrxYICLs
         DjhLdLDEVclU8eIVUrD8m6C1cH6QlEu5/L+kU4m7GQBhcwh4RTuVkmR00iPr9MFWT/zy
         Mzx63SjGwu89situ+1AhmGEjrO5KQV42FOYTxKsKPvcxihmHf5xcKmm/qdPqWi7KQrWe
         s+D3xZ9CWHT4uuoCVCZy2dQRaulwXhtMQM78Jaj0sPt9SeFUNczYoGWZkgeCaRBdbQBf
         /X1LFfhXKQpgtpGQEp0O5V/9OBF7CY9jmPeM7k5o/e3/hVcNd1lJ1Bp9inmikVHD8cR6
         Ka1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :message-id:subject:cc:from:to:date:dkim-signature;
        bh=OkwNj9mPXa7cpbjJxovVTnYfzzkSnM0K+3bN8LNLhNI=;
        fh=CAm64pb2c/h8g36OCGcWDlKx6qe61Fqy4eoGp3Z5JL8=;
        b=X4XpYj1yo7VYcZvjMzQlVIQKJKrHrG3rhANxl9KB8MjVx5paWgZj0vWOHmtdTpOjPz
         rGXWNz1UBbLZVBNuVaiRc89PEsB+HkP2DRAo+zrhXLGVGY+VFEl1rbXn2x7BE06DiZTo
         sV/ik5lhDx4J8QqyhIefx+GXWhCAJq4gw0J2Oq3dfDSkO/Mk9vnkKItsrJNqsjxp28p+
         vlg9oAwumcWxUhUJmzZ9L0ERHjeBWeHvefURS6e24gm0/wcTVdZLdzQIAf3q1kxH9IJM
         sPk4UWZtJg1C65Y2Bc2owv7ZnxhupxroSWcsy4zq0UmONGp4N6TjFiBpB65KKpraco4Q
         yTZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=UWp8vROk;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764874675; x=1765479475; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=OkwNj9mPXa7cpbjJxovVTnYfzzkSnM0K+3bN8LNLhNI=;
        b=CNy1C+X/LBXDYFCO9GYLvM4G3HwStxRa8tqpaZRkmkJP0jcwX/sptpUz4JxUyPTNYq
         5+opnqp+pUYKHyNaf+frQHx+0QAdbeLUOzcz7GvFgESfEnu3+n8vG677Mlfeim//79Ml
         smq0357h8XMwuwDZJfNKzbUGW8oqsZmhjS72CCgCG1LrUYKq5f6dIchG+vqwCsi+bRGc
         qA6T7LubfijDfEwb7UyCciynlaLeyYnnWritZD02sPR0P7IkPRkntIf/eJVE+e0v6ACY
         /MhV6nDUjnPn0NDIuOrZhlQK0lPqNKQbE5fgjpa8LY9iO1mZ18M9qslMIUZrFeSZSrGF
         3AZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764874675; x=1765479475;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=OkwNj9mPXa7cpbjJxovVTnYfzzkSnM0K+3bN8LNLhNI=;
        b=l7UP04MTKU00EnvKQQJp8cXIs+ZxX2+PiILMQzFSyRdlXafkkJqss+dFkH3vzNLOT4
         sfjGvJpmTfJGx9S5wFUpVqxNHRUJ0HBuZHddsa0LptOFfp1R5rWapOV9MVegB0BctG4w
         zfQysku7HCys4n+dcI7P2Vp0SBUlhBsSZZsKTbagTlGREMT6jV26+kAtYD6A09o6Wtp0
         uI60HBXdHddHZJw1cRIEugEN2vCnS/Ghb02mQGqCTAc6f7bhWq/wBSyOjAQVSYML3X0A
         4IvwzNYUKYWn1NhKDjIE3oaU8YrfZQYfzY1qN/ZugNlzNrR8Ezftl/pCy6IuwM8c7D9I
         sB2w==
X-Forwarded-Encrypted: i=2; AJvYcCXp4eg6SA+q5nrgCShOfmN1x6Fg8SFDNn5TrA36cyRWTtZPE2wUNduvIBPxQi3fMK1Ttok8tA==@lfdr.de
X-Gm-Message-State: AOJu0Ywdu6YcOwTdushYth++gjcuQ2Mdzpwnnw9DZWkoJo12zk8Ayd+/
	/OnbxYOm9T1y0fRf50J/9f+IswbfObeSwuEQY/LdYVPvnyFSmitv0Mav
X-Google-Smtp-Source: AGHT+IHu6TxyNU9C5zxHjMGOidxYOoHyrNmaxWHbGff45BgGa3zwg08d69jXqV/0bnswDoA6bOBrsQ==
X-Received: by 2002:a05:6512:39d2:b0:594:b2be:f3a with SMTP id 2adb3069b0e04-597d66c816amr1423058e87.25.1764874674894;
        Thu, 04 Dec 2025 10:57:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bzV4n0s6bnkRZhfrS4rdQjLadnKkdnTIlG07awwZtlfw=="
Received: by 2002:a05:6512:619:b0:597:d6dd:558b with SMTP id
 2adb3069b0e04-597d6dd55fbls290792e87.1.-pod-prod-09-eu; Thu, 04 Dec 2025
 10:57:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWOo2rboUNDP5zilqziW43IXk0KyZgWtIJ2NHWE8V3gpx5oY+HB5oPovfN86gY1D30TOctVZFGdgDw=@googlegroups.com
X-Received: by 2002:a05:6512:b88:b0:594:4ebf:e6bd with SMTP id 2adb3069b0e04-597d66a5110mr1462467e87.14.1764874672644;
        Thu, 04 Dec 2025 10:57:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764874672; cv=none;
        d=google.com; s=arc-20240605;
        b=AADWAi1nsytAwgKER7dzclnuZcbuJ6d5bWGIBXbAjOYB41UtlqevAYyCivifXPK5FJ
         TvP7++mtlHkAaIN0+eJR5gjf9PosUvFFYfPn6H9ib+TSmhRqVYmVIsCCOo+8sLW/7g0S
         DazN173vLm0Tt7Zj1sK++yTi16juJODTNn2444iANeI1CVPxQKRbFXjUbzojTX+0tPrU
         4aCMGCKKGfoYnUEU9OykxdnZmdZ0ldJkwEifsWbSGtW0uZUSuvCCSp4CuEld8AO3UnzN
         xFYCuQDc3jBWs3LlNk/0z8DuzwdfgauN2nljAHGpQhYW6qLvn3VnUnW5dbriHs/qpkuk
         ZSMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=ltaZZFKeOqkudCnNBawaeUoF6+LWTp0Fb4Ul14Ym3zU=;
        fh=gwjoxlsylfhJBVEflERE56rr73MTXCjecIodZvs0iMQ=;
        b=OodPNYC3ToSvGw5JVZ9H5reMG3i2isvGuLGS8neW4KD0XZGNzqyut9VZPhaMxCJUE6
         Qlc6eAWuFZlH8kbQ7wmmd9CvITTMAtvxeoGUFNbCmNtE4ClfjkFLEkkQpkI1KEl6BjJM
         2ZWHXVcXSSNWup06izxOc8h2zSMkYX+6U78g0N2e2n4jZYBBlCn8iC0f8uh7dXWonz/d
         9J/dVifUOj64iErVAWKGojxcfq6QoG50eFvyenE6heXz8Yd73aXkuZ5371ojSAfkqqiF
         fARR30SJX2fdRtyYOZn3Wgjeu2glXnNTcjkPoNQddhouGSnlPY5yDNvIoo+SPad1BDXy
         owuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=UWp8vROk;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106121.protonmail.ch (mail-106121.protonmail.ch. [79.135.106.121])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-597d7be3d45si31870e87.3.2025.12.04.10.57.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 10:57:52 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) client-ip=79.135.106.121;
Date: Thu, 04 Dec 2025 18:57:44 +0000
To: akpm@linux-foundation.org, urezki@gmail.com, dakr@kernel.org, vincenzo.frascino@arm.com, ryabinin.a.a@gmail.com, andreyknvl@gmail.com, kees@kernel.org, elver@google.com, glider@google.com, dvyukov@google.com
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: jiayuan.chen@linux.dev, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v3 0/3] kasan: vmalloc: Fixes for the percpu allocator and vrealloc
Message-ID: <cover.1764874575.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 40cdbf8e09bda976df8874685f1eeeae05616409
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=UWp8vROk;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

Patches fix two issues related to KASAN and vmalloc.

The first one, a KASAN tag mismatch, possibly resulting in a kernel
panic, can be observed on systems with a tag-based KASAN enabled and
with multiple NUMA nodes. Initially it was only noticed on x86 [1] but
later a similar issue was also reported on arm64 [2].

Specifically the problem is related to how vm_structs interact with
pcpu_chunks - both when they are allocated, assigned and when pcpu_chunk
addresses are derived.

When vm_structs are allocated they are unpoisoned, each with a different
random tag, if vmalloc support is enabled along the KASAN mode. Later
when first pcpu chunk is allocated it gets its 'base_addr' field set to
the first allocated vm_struct. With that it inherits that vm_struct's
tag.

When pcpu_chunk addresses are later derived (by pcpu_chunk_addr(), for
example in pcpu_alloc_noprof()) the base_addr field is used and offsets
are added to it. If the initial conditions are satisfied then some of
the offsets will point into memory allocated with a different vm_struct.
So while the lower bits will get accurately derived the tag bits in the
top of the pointer won't match the shadow memory contents.

The solution (proposed at v2 of the x86 KASAN series [3]) is to unpoison
the vm_structs with the same tag when allocating them for the per cpu
allocator (in pcpu_get_vm_areas()).

The second one reported by syzkaller [4] is related to vrealloc and
happens because of random tag generation when unpoisoning memory without
allocating new pages. This breaks shadow memory tracking and needs to
reuse the existing tag instead of generating a new one. At the same time
an inconsistency in used flags is corrected.

The series is based on 6.18.

[1] https://lore.kernel.org/all/e7e04692866d02e6d3b32bb43b998e5d17092ba4.1738686764.git.maciej.wieczor-retman@intel.com/
[2] https://lore.kernel.org/all/aMUrW1Znp1GEj7St@MiWiFi-R3L-srv/
[3] https://lore.kernel.org/all/CAPAsAGxDRv_uFeMYu9TwhBVWHCCtkSxoWY4xmFB_vowMbi8raw@mail.gmail.com/
[4] https://syzkaller.appspot.com/bug?extid=997752115a851cb0cf36

Changes v3:
- Reworded the 4th and 5th paragraphs after finding the vms[] pointers
  were untagged.
- Redo the patches by using a flag instead of a new
  __kasan_vmalloc_unpoison() argument.
- Added Jiayuan's patch to the series.

Changes v2:
- Redid the patches since last version wasn't an actual refactor as the
  patch promised.
- Also fixed multiple mistakes and retested everything.

Jiayuan Chen (1):
  mm/kasan: Fix incorrect unpoisoning in vrealloc for KASAN

Maciej Wieczor-Retman (2):
  kasan: Refactor pcpu kasan vmalloc unpoison
  kasan: Unpoison vms[area] addresses with a common tag

 include/linux/kasan.h | 16 ++++++++++++++++
 mm/kasan/common.c     | 34 ++++++++++++++++++++++++++++++++++
 mm/kasan/hw_tags.c    |  2 +-
 mm/kasan/shadow.c     |  4 +++-
 mm/vmalloc.c          |  8 ++++----
 5 files changed, 58 insertions(+), 6 deletions(-)

-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1764874575.git.m.wieczorretman%40pm.me.
