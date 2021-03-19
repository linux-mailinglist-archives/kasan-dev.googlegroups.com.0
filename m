Return-Path: <kasan-dev+bncBDQ27FVWWUFRBAPQ2KBAMGQEQVQVGBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9434B341FC8
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 15:41:06 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id a6sf7565399oic.22
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 07:41:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616164865; cv=pass;
        d=google.com; s=arc-20160816;
        b=QTfx9HOdhKgpJGPDDhY6ttmhmEOSl7JYhpltTWOhLNaKEapLwRwdpM8dF+n6qe/A/C
         fUu/VNPYOehNmHBCsDHAcWMk4OGoy3vu7CUxQqDJCXLiXqdaRxd2cAWqju1qzvfdBWmC
         qHMcQRIlG+OcDQmud9Vs5UjGMR92L169O5SXi7tY4JPVUuQ1V/wj0PxxGL79Y+DjXOjv
         /8JCkeTQjRDq6K06Hs/RUlm8I549hhTNb/UI2NqdoSzNKTwTc+2Sr0KnaK2Dy92gi0LE
         35Cotfw5LoPt/Lf90xYZKaZYeIa+9yfhRdF7AP4s1su+3WBxOrjSqFEXmFDZFYWXIZCn
         CgUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7Mql3A8ovSTcjzW5Q7B18bZsEcxsDgKgWK7+9gPeY68=;
        b=O99z2zqlASn5d2eT4zT57qnN7wWJzn+v1ZRYqlKQK6H6xj0ByIvKYnuX1yfiuuEpZN
         qmafhWvL9a2AlJK+5PEhmcjnp1ydYJphDDjPb7RvyuT8mrPZvvVp3N3JLYWuv1p3ZMW7
         yYEUHRJAS6IpJLvaM+eplrVnTp39CKxEylwiglrOTA7ABl8gA6tOWNmOJHc2mCx/jc5c
         q4AhE9ff1MUp1gdGi6EWF8cHmRzSy16fFeHi+Fzn5F/B0HpRmrP7vGBl8lZKMz1UMfTi
         H6vPi7bzy5dXwHkmceRDat2rmO4YsxbtBWrzmodr/DXuykEjN7AlyTj9OFeElDoWqGjw
         AgaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=GYlAFBv2;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7Mql3A8ovSTcjzW5Q7B18bZsEcxsDgKgWK7+9gPeY68=;
        b=SMkZTi89yBKiIHdOoBuECI7n4RyPEa30uMOePO/q9uKQceBe4aY2BhzxpFZKiM4l2R
         Kujtdu27Dou7LuLsVKbRL6Jx+zwde4YmAuqPrjCYTtcq0Mz+vUahVysZy/OzzrfkTn2F
         ++nA4Nk9S40FdQaYjxuO5fGu7n6EiSdgH8Gf4FU3FpXMr1CZsC1tlAtFzjVHaDegU037
         XBJgWsnow7eeDO4Kzl4Tye05V2cDYlAXOE6iZ1KY3GUEWKeTIuAnJ7/jo/Balbp5mHUD
         b14DYWadq0I3aoZK5KwaTMxKmf3fx2+NDIQnDKoO21i+oUfCVsaJOgKHM+NGz9h2jmAr
         w8pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7Mql3A8ovSTcjzW5Q7B18bZsEcxsDgKgWK7+9gPeY68=;
        b=V7hF4b3pwfEvPGZXkZQtuqmOBJIKttpEYRU253C0PgQ0UKXZcRkYFUzIak88PWzDrs
         9Il/XqIZLUpaO2qT6U2xtTKfE42aAXSmXvRa5nMHS5fJtJxDtHoX2b3dgHAXB1Jl10Ak
         MiV6qm0wX4aM3+fGaD//2iiiRQjgefUqHJ56b6Qf9fySVcz99B5GCA3yd+d28ZhWCSw3
         rnFz6YH2csCaXYsPGRzn1u+p7g9tMWAprV0LhOkPwMz5Okf5oo4zrvxN+ephtH3xrIxa
         V7/2KtOyXS3wcio5T3y6ypydiIMYsVDZPCIDz1dAnTVIPTEco+7aPiyWkzkDB7NRZysP
         6dUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530zKLQchqUgRQFY7VyCE8ZA/SzhZx0qxAbZkpL6piBH05UXCixE
	A+2kwkjZLsnM9VBGcu+Nbew=
X-Google-Smtp-Source: ABdhPJxCLfoH2Il0hMJ7XmwK2lNxGrxqd6MG3dPCyhkLwEF9GLXF3sWc1R9ZP7Fl+rzaYzDUtT5bZA==
X-Received: by 2002:a4a:e9a2:: with SMTP id t2mr1674101ood.15.1616164865301;
        Fri, 19 Mar 2021 07:41:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:13d0:: with SMTP id d16ls1467411oiw.10.gmail; Fri,
 19 Mar 2021 07:41:04 -0700 (PDT)
X-Received: by 2002:aca:fd13:: with SMTP id b19mr1262982oii.139.1616164864849;
        Fri, 19 Mar 2021 07:41:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616164864; cv=none;
        d=google.com; s=arc-20160816;
        b=YRMSlSFo6ZOq3Bny0a0Xl3aOvTVb69S6ijYyGo7h8/dwWRsQNdfiELFVeqBvcnUsLX
         0d6CqVPlFVBW58lCPU5UNQqwMfbnqPHrPArksmwoRtQbFaSBjla4lQMv96cYQA56MOM+
         6V9CpZRlYXtDgss+Yn3A9yt04WZRnBljmjkbIhXf/uOzuZa1LPGHDUcUw9Zu3Ht9m+cm
         Be+VPONGV3QghTDQJuogJhWybyUPjQPHq30F78mFYoTnr9iTqaXnRdSuSEhfBzAa9thv
         0F0WACpIXQfrHjV4arKICJ4v/KeU+iDmdlFPfNLhel+3RBNg8I+mHTwDn5ShzFwgaUok
         RYEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=JMTZPdTE/aMUDIoULLEYEVVyeOj9JMcW8Ag8gkApcG8=;
        b=zpTOqFF1623sXqOt8g+tdmLm16k256i+u5vTPIfLfWcTeg+ZCgl+pPqWGgTnEdZz2Y
         Mo2O9r3lCHFd2o267BIuIABULizrTgtTh363ZfM8ReHrhc0lMOaZA1ZfPYZTSM4jy9DU
         GHa/hrko+m5BG3swJJNK/DIcd2BKhQUFMU35DAt48a2qjGsRSbG4In5Dow6fb1HvvEcI
         p/I8artIrhtC+RBA37q3J0g5C4BqbZzMSl2VD/YNFPIwJQE32mbF/iyj0xKBYcBL8S5n
         aibFM3qwf6T4v/Y/WHN5fvYC3/nJXyITLRMv6FBVCGMc5DsCzvHn8zIynO7jH1eop5D6
         8KdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=GYlAFBv2;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id a4si228302oiw.5.2021.03.19.07.41.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Mar 2021 07:41:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id k23-20020a17090a5917b02901043e35ad4aso6789416pji.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Mar 2021 07:41:04 -0700 (PDT)
X-Received: by 2002:a17:90a:516:: with SMTP id h22mr9634409pjh.222.1616164864070;
        Fri, 19 Mar 2021 07:41:04 -0700 (PDT)
Received: from localhost (2001-44b8-111e-5c00-674e-5c6f-efc9-136d.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:674e:5c6f:efc9:136d])
        by smtp.gmail.com with ESMTPSA id l4sm5692224pgn.77.2021.03.19.07.41.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Mar 2021 07:41:03 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v11 0/6] KASAN for powerpc64 radix
Date: Sat, 20 Mar 2021 01:40:52 +1100
Message-Id: <20210319144058.772525-1-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=GYlAFBv2;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1033 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to 64-bit Book3S kernels running on the Radix MMU.

v11 applies to next-20210317. I had hoped to have it apply to
powerpc/next but once again there are changes in the kasan core that
clash. Also, thanks to mpe for fixing a build break with KASAN off.

I'm not sure how best to progress this towards actually being merged
when it has impacts across subsystems. I'd appreciate any input. Maybe
the first four patches could go in via the kasan tree, that should
make things easier for powerpc in a future cycle?

v10 rebases on top of next-20210125, fixing things up to work on top
of the latest changes, and fixing some review comments from
Christophe. I have tested host and guest with 64k pages for this spin.

There is now only 1 failing KUnit test: kasan_global_oob - gcc puts
the ASAN init code in a section called '.init_array'. Powerpc64 module
loading code goes through and _renames_ any section beginning with
'.init' to begin with '_init' in order to avoid some complexities
around our 24-bit indirect jumps. This means it renames '.init_array'
to '_init_array', and the generic module loading code then fails to
recognise the section as a constructor and thus doesn't run it. This
hack dates back to 2003 and so I'm not going to try to unpick it in
this series. (I suspect this may have previously worked if the code
ended up in .ctors rather than .init_array but I don't keep my old
binaries around so I have no real way of checking.)

(The previously failing stack tests are now skipped due to more
accurate configuration settings.)

Details from v9: This is a significant reworking of the previous
versions. Instead of the previous approach which supported inline
instrumentation, this series provides only outline instrumentation.

To get around the problem of accessing the shadow region inside code we run
with translations off (in 'real mode'), we we restrict checking to when
translations are enabled. This is done via a new hook in the kasan core and
by excluding larger quantites of arch code from instrumentation. The upside
is that we no longer require that you be able to specify the amount of
physically contiguous memory on the system at compile time. Hopefully this
is a better trade-off. More details in patch 6.

kexec works. Both 64k and 4k pages work. Running as a KVM host works, but
nothing in arch/powerpc/kvm is instrumented. It's also potentially a bit
fragile - if any real mode code paths call out to instrumented code, things
will go boom.

Kind regards,
Daniel

Daniel Axtens (6):
  kasan: allow an architecture to disable inline instrumentation
  kasan: allow architectures to provide an outline readiness check
  kasan: define and use MAX_PTRS_PER_* for early shadow tables
  kasan: Document support on 32-bit powerpc
  powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
  powerpc: Book3S 64-bit outline-only KASAN support

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210319144058.772525-1-dja%40axtens.net.
