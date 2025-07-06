Return-Path: <kasan-dev+bncBAABBX7IVLBQMGQE2BNDQII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4519CAFA6E1
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Jul 2025 19:37:37 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-60d3f6ca90esf1799114eaf.2
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 10:37:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751823455; cv=pass;
        d=google.com; s=arc-20240605;
        b=LckwxDZmKaV274iNn9u2FP15nQEWBW+S83BfYviHJEYgnDBU2+2yYmgoiE0P1dm8V/
         8N40wIrmL12hv028whQCUL/Ike5EBJVuEitbx+my0leXm73Nede0MD57oMEuS9FWZF9M
         7A7l81xK1AbnGhGJpAo6CoF46FAIv+p0g2yDCz6+Ao539f4MaxHhaJdXDHwogHbMHmAG
         hV7RpZGF7H+e4pc+qfm9bahw5RAJqgAl+mvTBd6D9sLlvwtglYvqNE2dI2VXs+5A65l7
         lit7nWI+dP0/RI6c1Xo7Pj5rjpSw5Qa89cFJhbMtsV5+caZXcAWcTITlVDay5qY8088A
         X8Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:dkim-signature;
        bh=qTKP5g6zAWGPbdrf/LoWUT0HyxpKVwYEdcQt1m5YlMc=;
        fh=jYM5VG7ORlj2UagjyyrarhIRldHXfOAAQTe0YumZjOA=;
        b=XQnkhiBbuF/jSYi20MNi7g98mIhDejmlw/K9jMUIWRJjyLAPfqAVB1xy3qvyjSO4mU
         ryTgmP0Xyr22DpOI3quqAgiPG1OUwtlFKhdskCEFkvLaBR08lGULXKeAL+FGmBvFDPQC
         wTTLEBpbmf568g6TjE4lfbqw/bqbyxkKhDISYiHXZa5F9fKRC751Pm7zCZAV3zTIWRsb
         lPaEdq1ziifzFN4mtYR8T5ojZL0cIjCjSKNY0nMAkvligvR8Yd0LXOj3qMnh1cG6h9im
         MilanLDBTy3Pyd5O4mVia6IpyfCTUfzYW0gXtLqBqLHzNT4MR5UzV1dTSYM3Vbz8WTZF
         lCQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mxfjiZoS;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751823455; x=1752428255; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qTKP5g6zAWGPbdrf/LoWUT0HyxpKVwYEdcQt1m5YlMc=;
        b=hBFpL6G99BPJmk4tRBbpTxGCkYiXva9YOUwUeLDKTdWZ5D43TKHn5ORo11wAodC5WE
         VXeNZDo3tykLhQAvSg7YqyfRpuT6n8QB9egos9JGnrXrmTF2tBZ7ptI9eQwY39F+jNDH
         ytwfyvrGBcvmRm4uqiQkiJUXTaHNmeubktZXtipQiSBwq6L/SOwYG/8ZThrdloJxXtfz
         8lpzxlcDgOuEF1j3z4nj1GHWY1NtCf9Qb/qnQWnKIgqe8TKf/C5G0O5QgVw1Ib4dMbbM
         hh6gaM5cQHyj5CxPwxI+bwrp32fbBn57Ayj61X9qymgqHEPeWZ5loUrGQnc1ZmhdVAhB
         iQBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751823455; x=1752428255;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qTKP5g6zAWGPbdrf/LoWUT0HyxpKVwYEdcQt1m5YlMc=;
        b=otmlWhrrK0zBU/hFfof491dPu5L1pWz4O20X/+0ahlZTNIXp+rl3N89FEhaxNQELFP
         OlU7Uuf1PN+skw5ldzwwKeQzvlSsx90lJGtLx92BYy2BlBzfQrNaxdOCo2b/v9U0MSlB
         +CnDQl4ZxXn9OFVewfIX4VU8/dAL3JKXx9gNscMB+zVIQ7HOABgSdWWgD4N84P3TCPta
         AmhFpr2eofcyEh6iNBQJe+WovhGcLjsE51WiTeRGSF5tPJTLY97Qitylqgqkr5vzy6Cq
         bPAfaM+6nnouwt2khHCMm2SdYi0VC3nHz0qIKPjgYy2pzoI685LmiExITzrZ5UYw2XBo
         hdBQ==
X-Forwarded-Encrypted: i=2; AJvYcCUKpW6gVJvagVsv5zvNeHfqBSJFh/6KKS66YvoIJ/246ZrDV8CdbRzVAhZc7kTcHASdsaNsDA==@lfdr.de
X-Gm-Message-State: AOJu0YxBngTpMNZ9GqrqcX0VQncLVK94owqtSnDU1k0ZyTsbGYGdKiXz
	+FezFeFfozoJrO3Q1d/5eeP/MmOw4Hu/cegm+uC1QBUkmphUqkGr7xDG
X-Google-Smtp-Source: AGHT+IGZRGF4+9RwD0xgmysBrgTWMN+TlkpafswOYVywdIci8GXbPGFGYw7ciWdW9jVSULgDH1a7zA==
X-Received: by 2002:a05:6820:1b1a:b0:611:9fd4:ac26 with SMTP id 006d021491bc7-61392bd519fmr5744838eaf.5.1751823455666;
        Sun, 06 Jul 2025 10:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdRLIw/FEC18KCjLc3yry5kptKJIhuAGYrNdNXukVAzzw==
Received: by 2002:a05:6820:4dfc:b0:611:96d6:4597 with SMTP id
 006d021491bc7-613955f2b20ls678089eaf.2.-pod-prod-07-us; Sun, 06 Jul 2025
 10:37:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXaow3vkxP8slKDF0h8p3JYmQRGqMIYOFOWAnKQSA6i3W0yjG15jNgF4zK8aERgFGU0Kzfm/vNurB0=@googlegroups.com
X-Received: by 2002:a4a:e90c:0:b0:611:75a8:f6ca with SMTP id 006d021491bc7-61392bd8e04mr7535773eaf.6.1751823454819;
        Sun, 06 Jul 2025 10:37:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751823454; cv=none;
        d=google.com; s=arc-20240605;
        b=DIB9VvuaM+fSUpGlRn+7AKxcmwlOhmE3ntiM9KY5Ljei7tbH3C8lXimiMRo3bsWctf
         54S3mLQDv4yJA4lNaWAbDABN2AHQq97ajkuTrbkX1e9oi6/Bk8zIpuQHOS5CI+YqTx7m
         S/21aoj0g2mkVFJsWjzPdTMxEO/VA4F10+eW+OEkkNDUJiu8WUw3NWN+ZQOtUS20EVdD
         FLV15SWY+t0n5191IbqqeX6+NQahZOtmi89kruwqcspnXUGnSCMb+StJPaibDQoHBAdl
         uJmRB7Zdbki67pkOxqM7TqOvr7/BgxXPS7+oVJ3R5F0c8v8JmwkZGzAv62xC/NG9CNRr
         OXSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=f9voBFlWHzeaC+iDj5Wl/SZbZdAKJR9r5mrtiRs6/es=;
        fh=bGOSWPRaEaNPf+ttcItAvdRcTCsALM11wypoPWX8Mxk=;
        b=d5+R2J+8hsbwQh6waDNxwzhWrPNWvUN8mUB6exg9o3N3AzZ007iBvU1q8XLDUJBhun
         dNNf/GezmsiNFB/1Bk+I5qwRL00D1CwH8BEswpWNaVl4OBKTgTJMiRJ4DKaNOI0tmhRQ
         kdNHAjtmy4otPCZ0jWPoWBGJiXXLIaa+RtB2cKsi5xnRjdE4A+HwZiMsuMtj//SfKtAF
         Ht8i+9+25rVRVe15HHHSyoQzwUJLEtYjl7uUegMKVBXilocmeq+yCW+D4mzVmC4fIfGC
         KXsAYPw5FWDvyyCMmDHjggyZC7Wr0AKerGahbmrVp+vkN6L82RpaHDPnjdTkxLxSeZGH
         HAYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mxfjiZoS;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-6138e4ad044si311006eaf.2.2025.07.06.10.37.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 10:37:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 0131561127;
	Sun,  6 Jul 2025 17:37:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 93105C4CEED;
	Sun,  6 Jul 2025 17:37:32 +0000 (UTC)
Date: Sun, 6 Jul 2025 19:37:32 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>
Subject: [RFC v2 0/5] Add and use seprintf() instead of less ergonomic APIs
Message-ID: <cover.1751823326.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mxfjiZoS;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

Hi Kees,

I've found some more bugs in the same code.  There were three off-by-one
bugs in the code I had replaced, and while I had noticed something
weird, I hadn't stopped to think too much about them.  I've documented
the bugs, and fixed them in the last commit.  I've also added an ENDOF()
macro to prevent these off-by-one bugs when we can avoid them.

This time I've built the kernel, which showed I had forgotten some
prototypes, plus also one typo.

See range-diff below.

This is still not complying to coding style, but is otherwise in working
order.  I'll send it as is for discussion.  When we agree on the
specific questions on the code I made in v1, I'll turn it into coding-
style compliant.


Have a lovely Sun day!
Alex

Alejandro Colomar (5):
  vsprintf: Add [v]seprintf(), [v]stprintf()
  stacktrace, stackdepot: Add seprintf()-like variants of functions
  mm: Use seprintf() instead of less ergonomic APIs
  array_size.h: Add ENDOF()
  mm: Fix benign off-by-one bugs

 include/linux/array_size.h |   6 ++
 include/linux/sprintf.h    |   4 ++
 include/linux/stackdepot.h |  13 +++++
 include/linux/stacktrace.h |   3 +
 kernel/stacktrace.c        |  28 ++++++++++
 lib/stackdepot.c           |  12 ++++
 lib/vsprintf.c             | 109 +++++++++++++++++++++++++++++++++++++
 mm/kfence/kfence_test.c    |  28 +++++-----
 mm/kmsan/kmsan_test.c      |   6 +-
 mm/mempolicy.c             |  18 +++---
 mm/page_owner.c            |  32 ++++++-----
 mm/slub.c                  |   5 +-
 12 files changed, 221 insertions(+), 43 deletions(-)

Range-diff against v1:
1:  2d20eaf1752e ! 1:  64334f0b94d6 vsprintf: Add [v]seprintf(), [v]stprintf()
    @@ Commit message
         Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
         Signed-off-by: Alejandro Colomar <alx@kernel.org>
     
    + ## include/linux/sprintf.h ##
    +@@ include/linux/sprintf.h: __printf(2, 3) int sprintf(char *buf, const char * fmt, ...);
    + __printf(2, 0) int vsprintf(char *buf, const char *, va_list);
    + __printf(3, 4) int snprintf(char *buf, size_t size, const char *fmt, ...);
    + __printf(3, 0) int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
    ++__printf(3, 4) int stprintf(char *buf, size_t size, const char *fmt, ...);
    ++__printf(3, 0) int vstprintf(char *buf, size_t size, const char *fmt, va_list args);
    + __printf(3, 4) int scnprintf(char *buf, size_t size, const char *fmt, ...);
    + __printf(3, 0) int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
    ++__printf(3, 4) char *seprintf(char *p, const char end[0], const char *fmt, ...);
    ++__printf(3, 0) char *vseprintf(char *p, const char end[0], const char *fmt, va_list args);
    + __printf(2, 3) __malloc char *kasprintf(gfp_t gfp, const char *fmt, ...);
    + __printf(2, 0) __malloc char *kvasprintf(gfp_t gfp, const char *fmt, va_list args);
    + __printf(2, 0) const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list args);
    +
      ## lib/vsprintf.c ##
     @@ lib/vsprintf.c: int vsnprintf(char *buf, size_t size, const char *fmt_str, va_list args)
      }
2:  ec2e375c2d1e ! 2:  9c140de9842d stacktrace, stackdepot: Add seprintf()-like variants of functions
    @@ lib/stackdepot.c: int stack_depot_snprint(depot_stack_handle_t handle, char *buf
     +	unsigned int nr_entries;
     +
     +	nr_entries = stack_depot_fetch(handle, &entries);
    -+	return nr_entries ? stack_trace_seprint(p, e, entries, nr_entries,
    ++	return nr_entries ? stack_trace_seprint(p, end, entries, nr_entries,
     +						spaces) : p;
     +}
     +EXPORT_SYMBOL_GPL(stack_depot_seprint);
3:  be193e1856aa ! 3:  e3271b5f2ad9 mm: Use seprintf() instead of less ergonomic APIs
    @@ Commit message
     
         mm/kfence/kfence_test.c:
     
    -            The last call to scnprintf() did increment 'cur', but it's
    -            unused after that, so it was dead code.  I've removed the dead
    -            code in this patch.
    +            -  The last call to scnprintf() did increment 'cur', but it's
    +               unused after that, so it was dead code.  I've removed the dead
    +               code in this patch.
    +
    +            -  'end' is calculated as
    +
    +                    end = &expect[0][sizeof(expect[0] - 1)];
    +
    +               However, the '-1' doesn't seem to be necessary.  When passing
    +               $2 to scnprintf(), the size was specified as 'end - cur'.
    +               And scnprintf() --just like snprintf(3)--, won't write more
    +               than $2 bytes (including the null byte).  That means that
    +               scnprintf() wouldn't write more than
    +
    +                    &expect[0][sizeof(expect[0]) - 1] - expect[0]
    +
    +               which simplifies to
    +
    +                    sizeof(expect[0]) - 1
    +
    +               bytes.  But we have sizeof(expect[0]) bytes available, so
    +               we're wasting one byte entirely.  This is a benign off-by-one
    +               bug.  The two occurrences of this bug will be fixed in a
    +               following patch in this series.
    +
    +    mm/kmsan/kmsan_test.c:
    +
    +            The same benign off-by-one bug calculating the remaining size.
     
         mm/mempolicy.c:
     
-:  ------------ > 4:  5331d286ceca array_size.h: Add ENDOF()
-:  ------------ > 5:  08cfdd2bf779 mm: Fix benign off-by-one bugs
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1751823326.git.alx%40kernel.org.
