Return-Path: <kasan-dev+bncBCF5XGNWYQBRBX7Z6CWAMGQEHBGPXTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id BE91282772E
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jan 2024 19:20:17 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-5c65e666609sf1709812a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jan 2024 10:20:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704738016; cv=pass;
        d=google.com; s=arc-20160816;
        b=msKr2uzQsrcqd8NSaofZQe/A9W4tJhgSdJtPW8czSgQVJi4o4Dtp+kjzf2v5xuhu8y
         2fYIhNaPuTnTPYaYwho+xxs8L4SeFL3iPiydTYD9lzB1LxBp+CAai+NJtwOG/wWZZGOM
         C+qmEW7ZddTfwbLGdHUbGJwc1B3FEaXlgDuxIc/v6ewnD21MITCiRSqjWtAnTxu+uSOl
         RB1aBukmorGhZmQkf1cOASXLKU8nlDsUdxd3JuGCG9HWmUv8xKsVTopEWAqLpRAKuEiZ
         KilDzWOA8jLjqvCSv+0gpMrsx+Nz7GR/Cy0FyHidh2/uyYPoNMSJoz1B1NsOHJmDQSoY
         pVsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=rEMGlySXX+B3aN2BoOl5JZ7pCNVsX7vQKY3+pKM0w2A=;
        fh=+o/KLGNoSpsOIIaqLLZqMltx9JoIXUP6jzUXm0bRQSA=;
        b=nPjMqr+/rRBHlvlK4R1eC+5RHOx7rH1MoKFqd2kOKXeE33jA5CFHKhTAgPU0WeHFGr
         4yIOskC+HAOcuBCggGrqEjoZ2eyPQ85mEtwOoF2FPy/dpS7uXy6lYFtiFbm9ssIsRuYb
         LpcaV6kev4K2diuAfubi+CHrreosR1uHhAlaep6TwRIL8Z42UOeXk8l2N9w+y+cWeqaa
         emAtNOI8TteAO8p+CxOxO4EMBdgYWhr/qJDPcHtVmMpGkqwvFaKhzJhPOxhYYTTR6vqm
         SMgzQx5WTXNXBfpvWts//VkSt4FXIQqtwypDl85c76KSThT+Wcj23beeS6Y6LYiMmtLd
         2lKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=GveqTEvn;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704738016; x=1705342816; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rEMGlySXX+B3aN2BoOl5JZ7pCNVsX7vQKY3+pKM0w2A=;
        b=muxlU/zuMlbE7buAgRoWXGEB63MIT89/7VvZRBKye8IDkhozNm0zPzLLIx+1jJNshh
         P/x0FzkQAp3+CSOlbtt5Hfv2QVE6GC0Rluu0x2xGfXfTj1276N6evBtPfI3giL3yVRc6
         E8nL66sf+TVN+ihk6iS6VYxJj57K9SKnYrhK133h2SWfim2L+mPCRsZev/uFC3ugb8Uc
         PMavS1rY+Hz4zeuGCA/G8kkBNyH/1tVqadL+IwT4audAJ9pfiyzlEbRNRrmziZhNtf4q
         y9b+ldKocL8E5nWkNWKks+ckIr9lWuyhmU1WqiB6Ce+b8VYNsy526UxjmnykuQ8GcKiU
         H5lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704738016; x=1705342816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rEMGlySXX+B3aN2BoOl5JZ7pCNVsX7vQKY3+pKM0w2A=;
        b=wqDwHagvd3mLeYYRwDfeS8PKJvI7UadcPEdQO/zR2Ng7s0EVJ/hLioHS72mLjyhcZ5
         W0dVoPQzpA6ROahVzrMUmKx5+e6JOUgdy35Ujyu7UV76juoKDxRSM6i9ArUyHJ11one9
         L4ua/DSMkukxgq/C77QHd/r1rHAHOSznVxGFT1z4kbDujvdVx4J4h0aWc3JstgNj0PfM
         JYpoZGBQONUjqTH5NBhmMMhAZkKljTuJCYhtOQQQ9hH4rhFsEAq2HZSLZ7Xoa+gRDy2/
         VELTmEO8ZvtqUpHYW9yVzz1HWxmcIbiApeyTfALmWcyfISbyZMgC+EZARZdgdiGihovA
         +uUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz2YeA/iILaCApfwFFZ23VinqbSpIsngOZRv/VKLaq1+pCgdkqK
	O0EY8osOOWnOyL0kcPhJZgI=
X-Google-Smtp-Source: AGHT+IEdhPvHTbLDWJbEgg/UaXTEQ1pJ8LZxjTCnI/H4moao5a2EyMysxSuBsZthXpEDj/IoexIyAw==
X-Received: by 2002:a17:902:784c:b0:1d5:36a9:10db with SMTP id e12-20020a170902784c00b001d536a910dbmr1609387pln.130.1704738015870;
        Mon, 08 Jan 2024 10:20:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:74c9:b0:1d4:b46d:8206 with SMTP id
 f9-20020a17090274c900b001d4b46d8206ls857848plt.0.-pod-prod-03-us; Mon, 08 Jan
 2024 10:20:14 -0800 (PST)
X-Received: by 2002:a17:903:32c8:b0:1d5:36b3:bd83 with SMTP id i8-20020a17090332c800b001d536b3bd83mr1896957plr.101.1704738014602;
        Mon, 08 Jan 2024 10:20:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704738014; cv=none;
        d=google.com; s=arc-20160816;
        b=M0lgBc3UV0lc3K0P7h58Vj+xqBMQQh6WtnUoeNA9xH2OAReKMFTRIytBky3CxhQtDc
         P+ycnKYGPctsBARUv3FUaa0WTjJE+8JfmfJayVHeRyuntvohS5Cun8oLJSt7CykO54YM
         3+7InwuryBrkhFu5QPnpRQJnVb7EtE5FJov+WLv4lPPJRTWBWcdozdXZ9Y8gD9qUUoIu
         7ig+R9jNK/QnLC6pldTIGGiYNn+VtnFsCWZNL6J3CUGkUuK9rnJrpDM7mNJQQdO8QJ5F
         sqm8Vk2ut41P4VgFUPRsDO3MFNjpEQSIb4rMY2VLUHPH53nw1l43q5zG4m1/xX3goriA
         uYJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=MqDz4oNfh2B5BR/R2EPy7vlFbl/dDn7Jawuse3WFwvo=;
        fh=+o/KLGNoSpsOIIaqLLZqMltx9JoIXUP6jzUXm0bRQSA=;
        b=FGAazFsP4hzqlBi4FiwUtHksFh/6IyrVN4xCK9C/d/YKmFi7ztbadzkS24TetUmRGJ
         L6nfviYRFo2zuqsSgJfCl5ePypm8I5piSRczUngLHd62VgeH0M1kE3SwlYm79Klrh7WM
         wnxwamiclv1VcoptHT9+Op+6jxqJodRj63biV0Fp0V34NCd40pAj8MrKzDTDZRjetfXn
         jSx6c4UYD9qaCq7dTlvSSfhXTbmEnm29w2z3SVtFyuu2PgJqcCd+jVxK3r2vJM+t5jnk
         KuoK8KE5uFaJBwJwR+fSn4vkRwPqUn1xa7TF+Jrc3aClax18KiU6YTLhbRCWYl+RHcmB
         H8nA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=GveqTEvn;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id u12-20020a170903304c00b001d3cc53eaacsi23368pla.6.2024.01.08.10.20.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Jan 2024 10:20:14 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-1d480c6342dso16970925ad.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Jan 2024 10:20:14 -0800 (PST)
X-Received: by 2002:a17:902:684f:b0:1d5:4dbf:6045 with SMTP id f15-20020a170902684f00b001d54dbf6045mr517599pln.86.1704738014214;
        Mon, 08 Jan 2024 10:20:14 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id d23-20020a170902729700b001d54b86774dsm205146pll.67.2024.01.08.10.20.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Jan 2024 10:20:13 -0800 (PST)
Date: Mon, 8 Jan 2024 10:20:13 -0800
From: Kees Cook <keescook@chromium.org>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
	Anders Larsen <al@alarsen.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Anna Schumaker <anna@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Azeem Shaikh <azeemshaikh38@gmail.com>,
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>,
	Chuck Lever <chuck.lever@oracle.com>, Dai Ngo <Dai.Ngo@oracle.com>,
	"David S. Miller" <davem@davemloft.net>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Geliang Tang <geliang.tang@suse.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Gurucharan G <gurucharanx.g@intel.com>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Jakub Kicinski <kuba@kernel.org>, Jeff Layton <jlayton@kernel.org>,
	Jesse Brandeburg <jesse.brandeburg@intel.com>,
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com,
	Kees Cook <keescook@chromium.org>, linux-hardening@vger.kernel.org,
	linux-nfs@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
	Luis Chamberlain <mcgrof@kernel.org>,
	Marco Elver <elver@google.com>,
	"Masami Hiramatsu (Google)" <mhiramat@kernel.org>,
	Neil Brown <neilb@suse.de>, netdev@vger.kernel.org,
	Olga Kornievskaia <kolga@netapp.com>,
	Paolo Abeni <pabeni@redhat.com>,
	Ronald Monthero <debug.penguin32@gmail.com>,
	Shiraz Saleem <shiraz.saleem@intel.com>,
	Stephen Boyd <swboyd@chromium.org>,
	"Steven Rostedt (Google)" <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>, Tom Talpey <tom@talpey.com>,
	Tony Nguyen <anthony.l.nguyen@intel.com>,
	Trond Myklebust <trond.myklebust@hammerspace.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Xu Panda <xu.panda@zte.com.cn>
Subject: [GIT PULL] hardening updates for v6.8-rc1
Message-ID: <202401081012.7571CBB@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=GveqTEvn;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Hi Linus,

Please pull these hardening updates for v6.8-rc1. There will be a second
pull request coming at the end of the rc1 window, as we can now finally
remove the "strlcpy" API entirely from the kernel. However, that depends
on other trees landing first. As always, my tree has been in -next the
whole time, and anything touching other subsystems was either explicitly
Acked by those maintainers or they were sufficiently trivial and went
ignored so I picked them up.

Thanks!

-Kees

The following changes since commit 98b1cc82c4affc16f5598d4fa14b1858671b2263:

  Linux 6.7-rc2 (2023-11-19 15:02:14 -0800)

are available in the Git repository at:

  https://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git tags/hardening-v6.8-rc1

for you to fetch changes up to a75b3809dce2ad006ebf7fa641f49881fa0d79d7:

  qnx4: Use get_directory_fname() in qnx4_match() (2023-12-13 11:19:18 -0800)

----------------------------------------------------------------
hardening updates for v6.8-rc1

- Introduce the param_unknown_fn type and other clean ups (Andy Shevchenko)

- Various __counted_by annotations (Christophe JAILLET, Gustavo A. R. Silva,
  Kees Cook)

- Add KFENCE test to LKDTM (Stephen Boyd)

- Various strncpy() refactorings (Justin Stitt)

- Fix qnx4 to avoid writing into the smaller of two overlapping buffers

- Various strlcpy() refactorings

----------------------------------------------------------------
Andy Shevchenko (5):
      params: Introduce the param_unknown_fn type
      params: Do not go over the limit when getting the string length
      params: Use size_add() for kmalloc()
      params: Sort headers
      params: Fix multi-line comment style

Christophe JAILLET (1):
      VMCI: Annotate struct vmci_handle_arr with __counted_by

Gustavo A. R. Silva (2):
      afs: Add __counted_by for struct afs_acl and use struct_size()
      atags_proc: Add __counted_by for struct buffer and use struct_size()

Justin Stitt (5):
      HID: uhid: replace deprecated strncpy with strscpy
      drm/modes: replace deprecated strncpy with strscpy_pad
      nvme-fabrics: replace deprecated strncpy with strscpy
      nvdimm/btt: replace deprecated strncpy with strscpy
      nvme-fc: replace deprecated strncpy with strscpy

Kees Cook (6):
      SUNRPC: Replace strlcpy() with strscpy()
      samples: Replace strlcpy() with strscpy()
      i40e: Annotate struct i40e_qvlist_info with __counted_by
      tracing/uprobe: Replace strlcpy() with strscpy()
      qnx4: Extract dir entry filename processing into helper
      qnx4: Use get_directory_fname() in qnx4_match()

Stephen Boyd (1):
      lkdtm: Add kfence read after free crash type

 arch/arm/kernel/atags_proc.c               |  4 +-
 drivers/gpu/drm/drm_modes.c                |  6 +--
 drivers/hid/uhid.c                         | 15 ++++----
 drivers/misc/lkdtm/heap.c                  | 60 ++++++++++++++++++++++++++++++
 drivers/misc/vmw_vmci/vmci_handle_array.h  |  2 +-
 drivers/nvdimm/btt.c                       |  2 +-
 drivers/nvme/host/fabrics.c                |  4 +-
 drivers/nvme/host/fc.c                     |  8 ++--
 fs/afs/internal.h                          |  2 +-
 fs/afs/xattr.c                             |  2 +-
 fs/qnx4/dir.c                              | 52 ++++----------------------
 fs/qnx4/namei.c                            | 29 ++++++---------
 fs/qnx4/qnx4.h                             | 60 ++++++++++++++++++++++++++++++
 include/linux/kfence.h                     |  2 +
 include/linux/moduleparam.h                |  6 +--
 include/linux/net/intel/i40e_client.h      |  2 +-
 kernel/params.c                            | 52 ++++++++++++++------------
 kernel/trace/trace_uprobe.c                |  2 +-
 net/sunrpc/clnt.c                          | 10 ++++-
 samples/trace_events/trace-events-sample.h |  2 +-
 samples/v4l/v4l2-pci-skeleton.c            | 10 ++---
 21 files changed, 208 insertions(+), 124 deletions(-)

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202401081012.7571CBB%40keescook.
