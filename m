Return-Path: <kasan-dev+bncBCD353VB3ABBBO5AYHAAMGQE4BME3XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A61EAA0116
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 06:06:21 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-2240a960f9csf42239785ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 21:06:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745899579; cv=pass;
        d=google.com; s=arc-20240605;
        b=THaSuA8D8deCs3tHYscZU0c0SeYqUUPOJ7pRIOine0qZ9VW+Z8E8CHD0zA3xJmHJE5
         5BX56ew7g2iexNAJ7fCX4Jz+id8Zl/ENxCGbxeqixhv8wkiSIsksIkHMZbwicMJGm6e7
         WZtT1Q6tyB/nu6CoWxGIlSBQmSfqYSNlkvsxgSAVspplVoxzdh5kl6NtU36BeN4ktZu2
         gg7sign8DZavhErvxoA87lwOMqDJ/vOhz6BuTvPT0p+ifdSy6yC+05gh98qQBxIsobaW
         mdZwvKuhIEr4YYvbpEHHjklMt+gAPUHPT8tB0suECiQwFstG31FdJPc2R01dvXMnb82z
         A9JA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=zJ2bohRSvY6pzS9PQ/afHRe2VcDIajFnVAKlTXqvzRE=;
        fh=PB6o6N7uFHZ5a7V3wXyKzZP+/J/bekHo1z+pW9HnRSU=;
        b=HPg9gcQBVprXrLYWeCrIcw4NSnDguXb2WC3r0gTvmMKp2/CuX4luQ4CqHKM9bLOuAE
         MXoRplYVSuMp7DsqLYcDjHD1kCGE4PLa/rzjkbMPwf87gnn+wg2jHLfTDM2r7LLGKBhg
         Zr0ZIR9IUclEuSls6SQ4dL+DPlA2LZt6suuofNKl0H+HonG3MG4gZDx23eYocQyWI6NZ
         K3Znjiwz7wLSzJji/6CXICc/Ft1ypZT/rDKr2tlVIK5X1gxc5/tPsWIWj5awX61Eupvb
         OtJutm3JvoxK7WzPKGCgc+C+uHewsTYkn009zAeZJszqUWIetKRhwuqqaQnSt8BPsJ3k
         EhSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lG9VsAzy;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745899579; x=1746504379; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:reply-to:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zJ2bohRSvY6pzS9PQ/afHRe2VcDIajFnVAKlTXqvzRE=;
        b=brUnffAWsRn9L/kmcKBmXR+eo7bcX4+WNu0jemmqlutE6mwswpTF4YkKdt8q6g7sWd
         TBbEsGkZ6h+v56ZHrusAG+Ov1KuS0x+dVLJpzUnoSve8QEVb7M2Qt2o3HiDRq6n+kDDe
         8dPs7UVq8yz8PX5oCh7FV7VlkmbMEQcF5oIuWED17P4hffzi7dFVt9xlNLk2w2THYo/W
         C8YpHqiIwaLdCBtEs2zbuEqiY1uY5wRBtRDugR+ESZNhO36d+NTDEmY3EwElThroETpF
         UlrdJYlaNHuViVEKRDiW7XNaPBL2h0fTGMY/AIacLdVVh2G4Nxv0I5nkXKQxFrl9UK7y
         DxUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745899579; x=1746504379;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:reply-to:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zJ2bohRSvY6pzS9PQ/afHRe2VcDIajFnVAKlTXqvzRE=;
        b=t2zIHNMAsFOvkZRakHX/16HFvagATpRgRZWyKDQDcxqMTTsFvdmWxV4XjYe+zsMPbu
         A4mgFWjpMN6bNSccN/B/cWSTt3v/tRVef3Ug9qKStroIz54RgCgsxZ9Bq56Wv8qUGfUE
         KH1t5qgxiIZPpEt9e+zkwZrPcVBzaLmQqwljYkxMoqX/8/xiPHRrd8/WHe+HmtD48Eyv
         pBvpenZOGa4udiTRWFWZG2heRqj+wdrf7PEsEkqjhSW1ViASDkcnl1t8MfhzpNsYMins
         zxJYR38TZW6d/i6kGKHnznM9ACwcQs3F+ECtkHSqJTOZo5Xv8JdVXSeul/6o1mZ/DXcU
         B2ag==
X-Forwarded-Encrypted: i=2; AJvYcCVqBq5mcj7IioYa9hl+H+ck6RAca57Hb2sWbmTKU4QjuDQImLa0KKq0hzQ2xJdlF58VJbaF9g==@lfdr.de
X-Gm-Message-State: AOJu0Yy8ywUx6ry/nLvIGUlqioIST7SLwzXf0ZDQYMu58i8vLCtuL8Az
	2gFJlUrD/VLe/Kxhl2vJr8aDiwSD1N3dF7jxqL1Cu2RWSC9e1yKC
X-Google-Smtp-Source: AGHT+IHy9LP3s5xl68YIL4l/uq0fD8l+dNKif7bDJuOk7iW4rhNS5JO8aKI3jPPqBIWiGICMA5xnQA==
X-Received: by 2002:a17:902:c40c:b0:223:6657:5008 with SMTP id d9443c01a7336-22dc6a0d4a4mr185737365ad.24.1745899579597;
        Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH1zQODtHwIuHfbhVSa1o5QMCi+QU5+OlKdYDAgHdvVdQ==
Received: by 2002:a17:903:3b87:b0:216:59e6:95c2 with SMTP id
 d9443c01a7336-22db0f67569ls21859685ad.0.-pod-prod-04-us; Mon, 28 Apr 2025
 21:06:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUu3gYgd9gjFezeWbSbAy3UXnJa+cruXvUBjpHT/9n9vFfIHMyl7E0c0EPveyZ9ywM528czJrKeSqs=@googlegroups.com
X-Received: by 2002:a17:902:f541:b0:223:fdac:2e4 with SMTP id d9443c01a7336-22dc69f5e37mr166540135ad.1.1745899578464;
        Mon, 28 Apr 2025 21:06:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745899578; cv=none;
        d=google.com; s=arc-20240605;
        b=fymYck7eAeUfQcXavW+9lde9mkEBX15PbgSvpLjdZ4T9bfBN0JGNh3FlUkRkYm3s3J
         6Feo/QPNnoBVaVTMGM/NgKl158VUqNJhIW3I+0kH0ck/z33lRmQumbyOrGxQkq7D8VEM
         1cUV8PApJ7HvEmd1NnZVZe2QGxIzub0f33/fB5Njta6R5EF5xZmHc6IpRtesXIYC5daZ
         +uvqiRvdfa1cb2hWnWFKdsFwOQc+TaY9kRy3IDwztfrVJceE9KLymNhtMjvpiejhgqlD
         3JtVCB9AQWARxGqeqENjKFd0VotO8hhuqxPOIW7ZCzBbMqioeTpEUJp98rm93QURXHg1
         UvFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=reply-to:cc:to:in-reply-to:references:message-id
         :content-transfer-encoding:mime-version:subject:date:from
         :dkim-signature;
        bh=DHY7yhZZbBEsyb+2Ly/Nb1eYeiuoEspG92fLONiY6Co=;
        fh=/bs3vO5UrVqo8T78tIeeq6rdQWrwj5Jc7+dDXJAvsfQ=;
        b=atrrEEAX1NURiAYgwl4X/dHLKqg+vZM6UwEwu+O4TAoaSWj5FzXHpbSFE5moTe9LHy
         omN+o0uIuk3m29EClxe1XUm48bR4c1wrkOduaWA3IYabE2/+OP1OfCZHs/DsUqdN0BFJ
         Ux2cJuHhAmxe9qPKMzR3l9q3IULMX9Mpo68XwVXXejda6/uS8Su5nHAvd8IZPXChFuVK
         i3ujE4NEYFkhMoN5cjasMn9APiCjqK2/1DZVldoNE23RJyu9QVTylpKf7nMgFyg/tr7F
         SNR1wuzp4NdbbXSGGIO41F56fOBa8SEM59atgJOkwRMDBOyhnq9A1W7vLgmgGRG59I1h
         HCJQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lG9VsAzy;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22db50f0457si4238175ad.7.2025.04.28.21.06.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Apr 2025 21:06:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 894DBA4BAEE;
	Tue, 29 Apr 2025 04:00:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id EE095C4CEF8;
	Tue, 29 Apr 2025 04:06:16 +0000 (UTC)
Received: from aws-us-west-2-korg-lkml-1.web.codeaurora.org (localhost.localdomain [127.0.0.1])
	by smtp.lore.kernel.org (Postfix) with ESMTP id E278EC369CB;
	Tue, 29 Apr 2025 04:06:16 +0000 (UTC)
From: "'Chen Linxuan via B4 Relay' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Apr 2025 12:06:07 +0800
Subject: [PATCH RFC v3 3/8] vfio/virtio: add __always_inline for
 virtiovf_get_device_config_size
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250429-noautoinline-v3-3-4c49f28ea5b5@uniontech.com>
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
In-Reply-To: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
To: Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>, 
 Christoph Hellwig <hch@lst.de>, Sagi Grimberg <sagi@grimberg.me>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Yishai Hadas <yishaih@nvidia.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
 Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>, 
 Kevin Tian <kevin.tian@intel.com>, 
 Alex Williamson <alex.williamson@redhat.com>, 
 Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, 
 Masahiro Yamada <masahiroy@kernel.org>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>, 
 Michal Hocko <mhocko@suse.com>, Brendan Jackman <jackmanb@google.com>, 
 Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>, 
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
 Peter Zijlstra <peterz@infradead.org>, 
 "Paul E. McKenney" <paulmck@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
 Juergen Gross <jgross@suse.com>, 
 Boris Ostrovsky <boris.ostrovsky@oracle.com>, 
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, 
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
Cc: linux-nvme@lists.infradead.org, linux-kernel@vger.kernel.org, 
 linux-mm@kvack.org, kvm@vger.kernel.org, virtualization@lists.linux.dev, 
 linux-integrity@vger.kernel.org, linux-kbuild@vger.kernel.org, 
 llvm@lists.linux.dev, Winston Wen <wentao@uniontech.com>, 
 kasan-dev@googlegroups.com, xen-devel@lists.xenproject.org, 
 Chen Linxuan <chenlinxuan@uniontech.com>, 
 Changbin Du <changbin.du@intel.com>
X-Mailer: b4 0.14.2
X-Developer-Signature: v=1; a=openpgp-sha256; l=3264;
 i=chenlinxuan@uniontech.com; h=from:subject:message-id;
 bh=xG7js8JRxRjbFUIGcKi60xVgk95Kd+hLnEeuvHk0cSk=;
 b=owEBbQKS/ZANAwAKAXYe5hQ5ma6LAcsmYgBoEFAwmuPV3ACiHfIboeRqguBq0EhDlCeY2gJxc
 awVBFVX6dWJAjMEAAEKAB0WIQTO1VElAk6xdvy0ZVp2HuYUOZmuiwUCaBBQMAAKCRB2HuYUOZmu
 i/7eD/9hIYexsn7L7GF/snRnakoE8V20CWkBNi/mt9lRdndsCiW2OdR1Ihha5YAXqecwmxRnfIk
 Emq8Rre/zUQpqoY7eJyR2xDIWhTnkwkCyfEyTsfGHJLEwQpKTt6VJJ194lzRgNJrsRGkdhoJgPI
 YVf5pd6n5+4vBUJ/2hfI/Wqt3KqqPR6vu9hUhNnSvGaEfJr67namCj1dKTEwipm+iyXGN7sYjwk
 snpKKFC8f1CyrsuOK1huwKroAFyXxK4bO9wRbSoE6Gt/WzfA3AIzffrZ/aMgOYpKOZs6Ing6PD3
 JJtFMLXppoFpuxaeXTedKMV2BuZ+QBRT8o4qDbJfIlRShfkM7nmkNgwKfyWdeXJVC/xO2NpbaXw
 oP4yE1mGjdBOkSpdcza79ucV0LSYANd8QnYJp5U0wRF5sJzj2Nll37E/9/W1L6yc4KSM3WdsvwP
 RsV1dnU8iFNZu61T95iCwa1GRo9dBbiQkjhkOvrBKEnM4ASeS1O0D2PdUlpWE7vO5rmS4F+3XCa
 Y/P1rp+j9DMaFuEPisA/6hp+L1E2HvBW5Md/Z6qu10+dwT1kPXvMWF0HUIgHhAppENa897twV7b
 6F9KYT4mFmdKNtZU6HSx6NzlGP2GxiJ1qZQP6mSPk+y5h2cOxYVABAdoN0CT/1P2jyc5Gq7LZo4
 ETnYNoxJgZ1iw4Q==
X-Developer-Key: i=chenlinxuan@uniontech.com; a=openpgp;
 fpr=D818ACDD385CAE92D4BAC01A6269794D24791D21
X-Endpoint-Received: by B4 Relay for chenlinxuan@uniontech.com/default with
 auth_id=380
X-Original-From: Chen Linxuan <chenlinxuan@uniontech.com>
Reply-To: chenlinxuan@uniontech.com
X-Original-Sender: devnull@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lG9VsAzy;       spf=pass
 (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org
 designates 147.75.193.91 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Chen Linxuan via B4 Relay <devnull+chenlinxuan.uniontech.com@kernel.org>
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

From: Winston Wen <wentao@uniontech.com>

Presume that kernel is compiled for x86_64 with gcc version 13.3.0:

  make defconfig
  ./scripts/kconfig/merge_config.sh .config <(
    echo CONFIG_VFIO=m
    echo CONFIG_VIRTIO_PCI=y
    echo CONFIG_VIRTIO_PCI_LIB_LEGACY=y
    echo CONFIG_VIRTIO_VFIO_PCI=m
    echo CONFIG_VIRTIO_VFIO_PCI_ADMIN_LEGACY=y
  )
  make KCFLAGS="-fno-inline-small-functions -fno-inline-functions-called-once" \
    drivers/vfio/pci/virtio/legacy_io.o

This results a compile error:

    CALL    scripts/checksyscalls.sh
    DESCEND objtool
    INSTALL libsubcmd_headers
    CC      drivers/vfio/pci/virtio/legacy_io.o
  In file included from <command-line>:
  drivers/vfio/pci/virtio/legacy_io.c: In function 'virtiovf_init_legacy_io':
  ././include/linux/compiler_types.h:557:45: error: call to '__compiletime_assert_889' declared with attribute error: BUILD_BUG_ON failed: !is_power_of_2(virtvdev->bar0_virtual_buf_size)
    557 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
        |                                             ^
  ././include/linux/compiler_types.h:538:25: note: in definition of macro '__compiletime_assert'
    538 |                         prefix ## suffix();                             \
        |                         ^~~~~~
  ././include/linux/compiler_types.h:557:9: note: in expansion of macro '_compiletime_assert'
    557 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
        |         ^~~~~~~~~~~~~~~~~~~
  ./include/linux/build_bug.h:39:37: note: in expansion of macro 'compiletime_assert'
     39 | #define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)
        |                                     ^~~~~~~~~~~~~~~~~~
  ./include/linux/build_bug.h:50:9: note: in expansion of macro 'BUILD_BUG_ON_MSG'
     50 |         BUILD_BUG_ON_MSG(condition, "BUILD_BUG_ON failed: " #condition)
        |         ^~~~~~~~~~~~~~~~
  drivers/vfio/pci/virtio/legacy_io.c:401:9: note: in expansion of macro 'BUILD_BUG_ON'
    401 |         BUILD_BUG_ON(!is_power_of_2(virtvdev->bar0_virtual_buf_size));
        |         ^~~~~~~~~~~~

BUILD_BUG_ON needs virtvdev->bar0_virtual_buf_size to be computed at
compile time. So we should mark virtiovf_get_device_config_size() with
__always_inline here.

Co-developed-by: Chen Linxuan <chenlinxuan@uniontech.com>
Signed-off-by: Chen Linxuan <chenlinxuan@uniontech.com>
Signed-off-by: Winston Wen <wentao@uniontech.com>
---
 drivers/vfio/pci/virtio/legacy_io.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/drivers/vfio/pci/virtio/legacy_io.c b/drivers/vfio/pci/virtio/legacy_io.c
index 832af5ba267c49a079009cfe0fa93c15ba7a490f..b6871d50b9f9e278ef3c49a9cb2baf474b8271c6 100644
--- a/drivers/vfio/pci/virtio/legacy_io.c
+++ b/drivers/vfio/pci/virtio/legacy_io.c
@@ -350,7 +350,7 @@ int virtiovf_open_legacy_io(struct virtiovf_pci_core_device *virtvdev)
 	return virtiovf_set_notify_addr(virtvdev);
 }
 
-static int virtiovf_get_device_config_size(unsigned short device)
+static __always_inline int virtiovf_get_device_config_size(unsigned short device)
 {
 	/* Network card */
 	return offsetofend(struct virtio_net_config, status);

-- 
2.43.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250429-noautoinline-v3-3-4c49f28ea5b5%40uniontech.com.
