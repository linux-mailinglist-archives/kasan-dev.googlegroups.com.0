Return-Path: <kasan-dev+bncBDOILZ6ZXABBBP4632UQMGQEKY3KF6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C339D7D4C78
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 11:32:49 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-5079641031asf4203530e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 02:32:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698139969; cv=pass;
        d=google.com; s=arc-20160816;
        b=ETDGkYqSGAaIr57jNdCgS8N+37OdcueCkWMfB1YyRjIzq1u50Nm13U5BG+rk96iBxO
         i+c/LgMk71lsnwEFaMYcD0CXMMy2qtJy6L8KXYUEggASa+ofN8Gk892ewN8SY2MCNK/d
         loUw6Y/CRdf+jt0ytm5sNrdcOZT15mPS7QXxW3y2L4o8vPaGs0WbNCmjn7l8h52Tdwq7
         6Abrstnl4UDZ5EkgaY2A0ygeLgI5TAqDnin7a7ZNzQouOm2RwIh9c6Ak8XqAr2xE9fo4
         scjA42E50xNJsg3Mf+gFUY2kvhMD2+cmWU9C9ozu/cz1+0QlGzMAawQKhfCi1744w5qS
         9hpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=v6HCahpqiAU2EEns4r61r1wUfMB25qZmAgstg7TGe1k=;
        fh=u+o5lMiXquI7xC/v11GZX0GTeTsM34rk11VKwaG3MXM=;
        b=wZD2eTzTJ1rTkp3wvfy6wAleMO4q6eXyLzjjZ43pn3MjLQYvI7dKotnWEshRG19io2
         Nlr2O/CvvCZUo9XGEI6/XKyVJj2a+jV1x8Usp5/yiX7nudGDBNgDPlM0WLfGz2toES9t
         KgN9mYIlv8Y4U1WO5ZGNcyycQ9Zu/OpZpQ9xo50kKt/j1R756ZqSsp9kjdoozAe/TvPq
         XMEowld0hJuZjqc5Cl14wh9gBw/oZ75yv8sHzUW8y70kz76++1g/KwAoNNpf7qh77KQu
         GqmhzSizy5Hp0ul7Q9tad0rf4fL6G7yEyEveynENNXG6f5pKvxD+fRKPLzN43Qjusksw
         21jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=oaHnXwhT;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698139969; x=1698744769; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=v6HCahpqiAU2EEns4r61r1wUfMB25qZmAgstg7TGe1k=;
        b=UYFWZG5AdgWcG6zXRCgqknfYFESkbx2sNHtl2QdtsSxL2mPCasch9X4l3Oh8NtiZMZ
         7Ut1xoya9vaHVdMK3gXbXVgPr6yZYPencBi8RAQNb0r/RnKCZUjfcZhjxDTwLHC4W5Tr
         QQIMQpUozvtRZKfINC9vWRMqD9r7poYWW+aPgmzt1NlL9B6bcvySlQwNQvrvbfRzg5ir
         +92tyycHYw6YsIPv4Fovv33fuwvWfP43T46kMzY81qZ0iVjfe6HAJjK6068E/erNcz2W
         B43DY79CfvU9yVvaefofM5i3cDg5V5SBfRFmscHrlj3zYdU8BEwyc3B6oewwDu/lBeRv
         dZxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698139969; x=1698744769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=v6HCahpqiAU2EEns4r61r1wUfMB25qZmAgstg7TGe1k=;
        b=Kj2l8w3QU09wWfDpIbuk+N8bJPtHtaWP1naGOoBVhzhPgkHSuQB94WKq0N+6GSe7qf
         qR7rV25kGBSCRJPTA12pp7C8vFSsk2By44LT41V+rgXwrowU5fqlMtY9uzGW6FuLG0XN
         BXmDPr56cirC2EdFBlVK/DHTM3L5fHssxaaqEW02XhvozjS4rJ0Kg8Jo+N8vLs0Sr2Y8
         WsA4JMi9ntMfKJyOffBqSmu3keqkjo6ueCqLw72TkoIYU23kK8LNFbOszETVQwdFEy6M
         4uWD9nSAMPrydOIeLYPNJiW9jWrv7MvXJZKxf1K2ddDK+gvan7ozLUfvac2lY904Jhf7
         uvOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyQflhkUXF3f6MxDzdTZlJZxKMTuh+zieFh70p1mJZEdqx4K1kE
	WEDHlPBwwbt/XIGrXloehWk=
X-Google-Smtp-Source: AGHT+IEERWHdq5QeA7Koop5qnak45l3h2Z2P5lHbBdidjBI8WFKPT4sfIRBynCNj8xfvxvCfT43hCw==
X-Received: by 2002:a19:ee14:0:b0:507:a8f4:9543 with SMTP id g20-20020a19ee14000000b00507a8f49543mr7760505lfb.42.1698139967800;
        Tue, 24 Oct 2023 02:32:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ad0:b0:503:d3c2:f4fa with SMTP id
 n16-20020a0565120ad000b00503d3c2f4fals553203lfu.0.-pod-prod-05-eu; Tue, 24
 Oct 2023 02:32:46 -0700 (PDT)
X-Received: by 2002:ac2:51a3:0:b0:507:9618:d446 with SMTP id f3-20020ac251a3000000b005079618d446mr7081869lfk.61.1698139965819;
        Tue, 24 Oct 2023 02:32:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698139965; cv=none;
        d=google.com; s=arc-20160816;
        b=DjhC2N1tui+r04NTi8DRjLI4+MwqcNhmjQv+bnkFq4uG3cu1fMQROhAFuDMovEX1Ax
         IooQiFAwVBUCAQRIpByPJX8ZBqvBTgmsZS2cgv/jEgg/qWZU0uTO88dDUEMzbyfJ7G3A
         F7G+0gO9NHdc36Rgr6ZBAz0AB7rt9i3F+ZQV76r3MwgoRMSJ5EVwTKu5iZBLv6qrfXOS
         9wbiyphYJZXnt/2yXJ419Qcb683PlNJEwWyM9KBN85a+sQJX6RchKMu3Hj6gigQPhFPL
         vbzxQsUpk8RO3PjB/pAfEH1SVrxdSR/m5JxE0fXPzCUQ1zv9sgKW5DfrkQVnlQKTrUHP
         KRVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=1Rw/jYGs06Fd+viAjMbCyeWD4YePZEfjBTa+fHZnvXM=;
        fh=u+o5lMiXquI7xC/v11GZX0GTeTsM34rk11VKwaG3MXM=;
        b=R0isFI940V9iRwrUIRxXG2ZiWhfNDdMOZ4Ah7JU8XY+V/dTzHo60AYbKvKxXUAmrkF
         lXb6JnXG+k3eRc4UuU7OrdrmBNmC6oAgwGekBx0Vlb6UhaNUFcllTkVu5f5LcXTLZETK
         0XRsCWJSHmyWxf3NP+LjH41qa/pnYPw9xB1y0UFpIvDYhKeQluZztCG5e9rCbfKVdJz1
         qJi82xWfcZqqVDDoamLtSU782qoifkjLakpRw9CJobImzCo5IlJ3MzcJYahnYCz5g5Yv
         7rTO/6xfF2WnslzPfkTuCzPIeqDU3XmNV2y1bjbIyR7yvBhyi2cH77kOrNzSpiKDBZ8+
         6JxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=oaHnXwhT;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id d29-20020a0565123d1d00b005008765a16fsi386094lfv.13.2023.10.24.02.32.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 02:32:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id 2adb3069b0e04-507d7b73b74so6178965e87.3
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 02:32:45 -0700 (PDT)
X-Received: by 2002:ac2:4202:0:b0:500:9214:b308 with SMTP id y2-20020ac24202000000b005009214b308mr8046002lfh.65.1698139965282;
        Tue, 24 Oct 2023 02:32:45 -0700 (PDT)
Received: from mutt (c-9b0ee555.07-21-73746f28.bbcust.telenor.se. [85.229.14.155])
        by smtp.gmail.com with ESMTPSA id c12-20020ac25f6c000000b004fbc82dd1a5sm2063075lfc.13.2023.10.24.02.32.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Oct 2023 02:32:44 -0700 (PDT)
Date: Tue, 24 Oct 2023 11:32:43 +0200
From: Anders Roxell <anders.roxell@linaro.org>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v3 00/19] stackdepot: allow evicting stack traces
Message-ID: <20231024093243.GA3298341@mutt>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: anders.roxell@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=oaHnXwhT;       spf=pass
 (google.com: domain of anders.roxell@linaro.org designates
 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On 2023-10-23 18:22, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Currently, the stack depot grows indefinitely until it reaches its
> capacity. Once that happens, the stack depot stops saving new stack
> traces.
> 
> This creates a problem for using the stack depot for in-field testing
> and in production.
> 
> For such uses, an ideal stack trace storage should:
> 
> 1. Allow saving fresh stack traces on systems with a large uptime while
>    limiting the amount of memory used to store the traces;
> 2. Have a low performance impact.
> 
> Implementing #1 in the stack depot is impossible with the current
> keep-forever approach. This series targets to address that. Issue #2 is
> left to be addressed in a future series.
> 
> This series changes the stack depot implementation to allow evicting
> unneeded stack traces from the stack depot. The users of the stack depot
> can do that via new stack_depot_save_flags(STACK_DEPOT_FLAG_GET) and
> stack_depot_put APIs.
> 
> Internal changes to the stack depot code include:
> 
> 1. Storing stack traces in fixed-frame-sized slots; the slot size is
>    controlled via CONFIG_STACKDEPOT_MAX_FRAMES (vs precisely-sized
>    slots in the current implementation);
> 2. Keeping available slots in a freelist (vs keeping an offset to the next
>    free slot);
> 3. Using a read/write lock for synchronization (vs a lock-free approach
>    combined with a spinlock).
> 
> This series also integrates the eviction functionality in the tag-based
> KASAN modes.
> 
> Despite wasting some space on rounding up the size of each stack record,
> with CONFIG_STACKDEPOT_MAX_FRAMES=32, the tag-based KASAN modes end up
> consuming ~5% less memory in stack depot during boot (with the default
> stack ring size of 32k entries). The reason for this is the eviction of
> irrelevant stack traces from the stack depot, which frees up space for
> other stack traces.
> 
> For other tools that heavily rely on the stack depot, like Generic KASAN
> and KMSAN, this change leads to the stack depot capacity being reached
> sooner than before. However, as these tools are mainly used in fuzzing
> scenarios where the kernel is frequently rebooted, this outcome should
> be acceptable.
> 
> There is no measurable boot time performance impact of these changes for
> KASAN on x86-64. I haven't done any tests for arm64 modes (the stack
> depot without performance optimizations is not suitable for intended use
> of those anyway), but I expect a similar result. Obtaining and copying
> stack trace frames when saving them into stack depot is what takes the
> most time.
> 
> This series does not yet provide a way to configure the maximum size of
> the stack depot externally (e.g. via a command-line parameter). This will
> be added in a separate series, possibly together with the performance
> improvement changes.
> 
> ---
> 
> Changes v2->v3:
> - Fix null-ptr-deref by using the proper number of entries for
>   initializing the stack table when alloc_large_system_hash()
>   auto-calculates the number (see patch #12).
> - Keep STACKDEPOT/STACKDEPOT_ALWAYS_INIT Kconfig options not configurable
>   by users.
> - Use lockdep_assert_held_read annotation in depot_fetch_stack.
> - WARN_ON invalid flags in stack_depot_save_flags.
> - Moved "../slab.h" include in mm/kasan/report_tags.c in the right patch.
> - Various comment fixes.
> 
> Changes v1->v2:
> - Rework API to stack_depot_save_flags(STACK_DEPOT_FLAG_GET) +
>   stack_depot_put.
> - Add CONFIG_STACKDEPOT_MAX_FRAMES Kconfig option.
> - Switch stack depot to using list_head's.
> - Assorted minor changes, see the commit message for each path.
> 
> Andrey Konovalov (19):
>   lib/stackdepot: check disabled flag when fetching
>   lib/stackdepot: simplify __stack_depot_save
>   lib/stackdepot: drop valid bit from handles
>   lib/stackdepot: add depot_fetch_stack helper
>   lib/stackdepot: use fixed-sized slots for stack records
>   lib/stackdepot: fix and clean-up atomic annotations
>   lib/stackdepot: rework helpers for depot_alloc_stack
>   lib/stackdepot: rename next_pool_required to new_pool_required
>   lib/stackdepot: store next pool pointer in new_pool
>   lib/stackdepot: store free stack records in a freelist
>   lib/stackdepot: use read/write lock
>   lib/stackdepot: use list_head for stack record links
>   kmsan: use stack_depot_save instead of __stack_depot_save
>   lib/stackdepot, kasan: add flags to __stack_depot_save and rename
>   lib/stackdepot: add refcount for records
>   lib/stackdepot: allow users to evict stack traces
>   kasan: remove atomic accesses to stack ring entries
>   kasan: check object_size in kasan_complete_mode_report_info
>   kasan: use stack_depot_put for tag-based modes

Tested-by: Anders Roxell <anders.roxell@linaro.org>

Applied this patchset to linux-next tag next-20231023 and built an arm64
kernel and that
booted fine in QEMU.

Cheers,
Anders

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024093243.GA3298341%40mutt.
