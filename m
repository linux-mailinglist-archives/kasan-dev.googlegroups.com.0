Return-Path: <kasan-dev+bncBCMIZB7QWENRBBW2ULCAMGQEEVQYOTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 05E90B14CCF
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 13:14:17 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-33212ba3b7asf6290491fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 04:14:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753787656; cv=pass;
        d=google.com; s=arc-20240605;
        b=E0VHGWU8E+76cAz048P7TIDUu5vxxBD+D2Nm2SrzTmrVdryu23YahS9phn5oQ5aH6D
         LNbpkOgsRBAQH7mPLn7sR2VixCi7HI7ABWnRa6Oa4fKaatUJQvD04GONUm8KjYpN8W0Z
         x6LCFGtguL1uUQOMhb0vO4sKZhTWit2Fh2/Qd22tv5U/9rcpGxBmIVI7Dtx5+IWu+T8H
         TWjVSI6l4X19AzIZv8j04Lr5xHBywqcsJRhmMY4PYxrV9hXLz726nUP5rzdT7BhHtzLi
         GaXCtpM/4xz+p7vkNz1T+m+lzkPaB6d8yCv86e5Zlb6LbuBKx9k0rWCoLc2RiZVQQRz8
         aJzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YTwNQkTwcjDy2updUjiznHlsjbd+Y1Cpbb96Ppw+rdU=;
        fh=9WYgxteDqq4KzufxOSnUYP5kQ/7S8Rtp1gVbp6nSWR8=;
        b=j6qiQymN0yETsezzQbytaUhD7kjcjdWGI0e5tpKr/lPZS+qsMNY/BZz/9QvXgPVHWq
         2r6ODxc3ZOHJaZgL3zikIgFACJh7FjpxvqYLHlvb84bYNXoRBQpp0zLnMmNIenVmu7Ez
         YowMtXfcaV/YIuw8MA3USFi/wOSfvcuetz8wpIblgHpTVLnlewshD6qpy6rtpTFIVJDC
         AgAg9/YdvbCYF4Yc53gaRjbCRoIe0nfLwLfi1+2xQG49y9tgdZdKQIh4vH685Fq6YsGL
         ybYzBEFPeRfUJ54SCWMogn9BYcIjDCBXb1Yo/pAQ8d1XZQLZEvzw+AFT6t4DwqtY8YRS
         Wu7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FteyfzRZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753787656; x=1754392456; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YTwNQkTwcjDy2updUjiznHlsjbd+Y1Cpbb96Ppw+rdU=;
        b=Cltf6OHhmafGn2rIQgAySWdOjiJED613ARbMnYK6op2ZPGRREN6sejo1JIOYjOo/JU
         HRwjT9IvjyWI9/dBZT1716JGGLhxGs3TU2oSgErZUwfG8izm9/icxuvusgUOctUilLDL
         AmFygqpEyAwiHIlnt5YkEZg2LolfaBysiXqmkjHw7EzPNGtNehHLiOVRS6oBRm2m9fKS
         F4xaJV/Vh/D8g1ySfAVO6KWt4UD4a3bd8s0vWFZpuleon0uTb+cJh17iO+Bd5hBpXU0U
         oV5vuxYsmPw1CRth/atZ9ttj2igmwapG9N/OB3hbtCqSGsEDA9cR8ujmMDqqomq3NZW/
         /A8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753787656; x=1754392456;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YTwNQkTwcjDy2updUjiznHlsjbd+Y1Cpbb96Ppw+rdU=;
        b=cB4HQfIZdhy3evxd0BI8ygHyW6VJ9yqCrw7/wIIZFYfo3Jw5KGmiL2rX3xOHPR/VaG
         qm+xcvzKwcUl3Y0XgfY6fneo0SA3nJeyJGLoUXPp33m03yCbE6OPi5hgJVOJf8D9E47d
         k4/DkgJk+Z/NQPihUFUsXfpag0mMkklcCmw5DmHqCfP9WF/bqU630jpYdvw0gvGy+P6C
         cSTpg9iXPRJzogPSBlmiaZhy4Bo+BqawicByRy52RSFBvc83fPTqUr1kXmHOaCUdnmnl
         0fRdkYn+LRYlE7Rs2d0GyRDl6bY5yhVlj0GZL9yp/T/dYQrzLzkRtNEAITuwmOLCjeOd
         qrBw==
X-Forwarded-Encrypted: i=2; AJvYcCV+RaT92/SVZyymDnzkDJANBgEUle/cQD4OVbGCL10ketE7LLaGxFq943I4cX1zxMhHuqggJA==@lfdr.de
X-Gm-Message-State: AOJu0Yyh8y5tFylG3Ajgm6eTeC/R3CI1gW/crIUTBTwyw2Zl/rc9yseA
	F2ifyIcajqxjUI5s017efXDtcUfmAOBmsNRr007QcChFbJvCy4fnGASW
X-Google-Smtp-Source: AGHT+IFY8UJm3GXxzOTboyX2JfAEfiXbPyMBLXla/yatsbdP3BIbw7tOgVzKXsLkO3MJE6Fb4ppWlg==
X-Received: by 2002:a05:6512:10d5:b0:55b:58f3:1598 with SMTP id 2adb3069b0e04-55b5f48ee78mr3938320e87.40.1753787655615;
        Tue, 29 Jul 2025 04:14:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZerOzfJ9N2PE7h0vJEEwp7TokiMoKAxK2tSohqmi178gQ==
Received: by 2002:a05:6512:461c:b0:55b:65e4:207b with SMTP id
 2adb3069b0e04-55b65e420a9ls829013e87.2.-pod-prod-08-eu; Tue, 29 Jul 2025
 04:14:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWh5pky8a6Izr+eMkZ3Q8GspAc1OPXfiMvCX63Eb8dVYUJ1/HpPZeD2dxcAjgPbuU+soUuyca/nBgw=@googlegroups.com
X-Received: by 2002:a05:6512:124d:b0:553:3407:eee0 with SMTP id 2adb3069b0e04-55b5f3d5c13mr4352014e87.4.1753787652517;
        Tue, 29 Jul 2025 04:14:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753787652; cv=none;
        d=google.com; s=arc-20240605;
        b=KRip0gdaYR/Xic6on8JC+XtHQZHdUMx7xO+O/4g/zRhhQ/2b0Bu4A/d+MfON/doT+Q
         zADAU7FZ4dQ71vXsyw2Fk7Y+ZETW0mP+JX7/SKj/32AASH0x67z5lL8ZRhGTlo9m/0YG
         ShvB9eofsPuejpSakXB9J5jB9rBwQ854N4nQZwZkxyNgGaGD64ypZzinO4e0KBG7TOLH
         j79LxrMSn5m3+Fwq/uA3K+9XZ08nDTSKYUlQ/B1Gi6NCJ8tWDLxOK66Q+wpkq993H0jO
         FiOB0leKwFBzEh0BVakkNmtfTRcHlQGFAApyPmVehCEdtky4oSOBx/Qd/BCsZZ6rc84g
         S8Bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mh389HBylGMlNQkfOeOZnOe2F5PAgAYVZIhMDMwa32I=;
        fh=A/PWUfETuGAFRvZ8IZ5v6cGX3AZddARxXVde4uLnhV8=;
        b=YRk+n2DMVfgJnf5DNMGQq+yTTvv54beXTN0BRJvms5I4NSKMO1gyDQRhFKlaQj+LYW
         l+zK4zYxTKeCXAdPyYhqnvRvxsWYjCMKOtVmq1gOLHrof43Lo8M/DJn7kkuOVdjBZzsZ
         B1pXeGs26CmSxwpUpgXZuGt17eSPD8GBfBlG/D7g3aWki2HsL1dNrwtJJT39i08uk5Wr
         5ontV78ioYrSEDwvjuEI7VAp1iw6Gy5k2pbYe+UQ5I1YsIpEAcX+Ot7n48Bo6IovTmRM
         6eeTU8N15ouHkabxSbor/nfind9FBcdsROkP+IjkDXHQ9+pRDwTUZV+5km11Fxbu9w/u
         CXqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FteyfzRZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22e.google.com (mail-lj1-x22e.google.com. [2a00:1450:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b633171d0si91694e87.7.2025.07.29.04.14.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 04:14:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e as permitted sender) client-ip=2a00:1450:4864:20::22e;
Received: by mail-lj1-x22e.google.com with SMTP id 38308e7fff4ca-33216091f46so7171991fa.3
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 04:14:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUWvVyUK05Nc3+MZbOI/WAenWLb6E5SLzUYZwXMwiBFCw0Hinn8+iGcefecQ8YP3JqBvw5YtzHx4ZA=@googlegroups.com
X-Gm-Gg: ASbGncu1nRCdWFK41QSw+Hf6wcREFzlSo1abeyE78aEatOrcz8IJrIDKPaMGibG7IoL
	GvWo1R0OFNb8bV2fIjSIMK4QJoupg19/qkwaobj11B+R78UKdgl4mTX7JfSSf6eLUu+tr5NDI/v
	VHxiKBGVAsLj+gZX+2hWYAUyp8qZEXwhs4pKRSoxZ4P1XQgXD9YWSv7X/IwnoBGek6Rdpkyia1F
	EUwdDg939s0Yn9D72j8v9Nxuv7fmHSE0KBukg==
X-Received: by 2002:a05:651c:1118:10b0:32b:8778:6f0a with SMTP id
 38308e7fff4ca-331ee7dd1cemr28381121fa.27.1753787651778; Tue, 29 Jul 2025
 04:14:11 -0700 (PDT)
MIME-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com> <20250728152548.3969143-8-glider@google.com>
In-Reply-To: <20250728152548.3969143-8-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Jul 2025 13:14:00 +0200
X-Gm-Features: Ac12FXwAMv8eL61LZ2q7cUqyG_EAxEjhHKT3t93dxq4uwCuf7mFhx_izynP-MnE
Message-ID: <CACT4Y+YLMO8hE3GqnXpSjoCD=PbFjGNWcKSN0BH10ASMHkHN8A@mail.gmail.com>
Subject: Re: [PATCH v3 07/10] kcov: add ioctl(KCOV_UNIQUE_ENABLE)
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FteyfzRZ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 28 Jul 2025 at 17:26, Alexander Potapenko <glider@google.com> wrote:
>
> ioctl(KCOV_UNIQUE_ENABLE) enables collection of deduplicated coverage
> in the presence of CONFIG_KCOV_ENABLE_GUARDS.
>
> The buffer shared with the userspace is divided in two parts, one holding
> a bitmap, and the other one being the trace. The single parameter of
> ioctl(KCOV_UNIQUE_ENABLE) determines the number of words used for the
> bitmap.
>
> Each __sanitizer_cov_trace_pc_guard() instrumentation hook receives a
> pointer to a unique guard variable. Upon the first call of each hook,
> the guard variable is initialized with a unique integer, which is used to
> map those hooks to bits in the bitmap. In the new coverage collection mode,
> the kernel first checks whether the bit corresponding to a particular hook
> is set, and then, if it is not, the PC is written into the trace buffer,
> and the bit is set.
>
> Note: when CONFIG_KCOV_ENABLE_GUARDS is disabled, ioctl(KCOV_UNIQUE_ENABLE)
> returns -ENOTSUPP, which is consistent with the existing kcov code.
>
> Measuring the exact performance impact of this mode directly can be
> challenging. However, based on fuzzing experiments (50 instances x 24h
> with and without deduplication), we observe the following:
>  - When normalized by pure fuzzing time, total executions decreased
>    by 2.1% (p=0.01).
>  - When normalized by fuzzer uptime, the reduction in total executions
>    was statistically insignificant (-1.0% with p=0.20).
> Despite a potential slight slowdown in execution count, the new mode
> positively impacts fuzzing effectiveness:
>  - Statistically significant increase in corpus size (+0.6%, p<0.01).
>  - Statistically significant increase in coverage (+0.6%, p<0.01).
>  - A 99.8% reduction in coverage overflows.
>
> Also update the documentation.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>


> ---
> v3:
>  - s/check_kcov_mode/get_kcov_mode in objtool
>
> v2:
>  - Address comments by Dmitry Vyukov:
>    - rename CONFIG_KCOV_ENABLE_GUARDS to CONFIG_KCOV_UNIQUE
>    - rename KCOV_MODE_TRACE_UNIQUE_PC to KCOV_MODE_UNIQUE_PC
>    - simplify index allocation
>    - update documentation and comments
>  - Address comments by Marco Elver:
>    - change _IOR to _IOW in KCOV_UNIQUE_ENABLE definition
>    - rename sanitizer_cov_write_subsequent() to kcov_append_to_buffer()
>  - Use __test_and_set_bit() to avoid the lock prefix on the bit operation
>  - Update code to match the new description of struct kcov_state
>  - Rename kcov_get_mode() to kcov_arg_to_mode() to avoid confusion with
>    get_kcov_mode(). Also make it use `enum kcov_mode`.
>
> Change-Id: I9805e7b22619a50e05cc7c7d794dacf6f7de2f03
> ---
>  Documentation/dev-tools/kcov.rst |  43 ++++++++
>  include/linux/kcov.h             |   2 +
>  include/linux/kcov_types.h       |   8 ++
>  include/uapi/linux/kcov.h        |   1 +
>  kernel/kcov.c                    | 164 ++++++++++++++++++++++++++-----
>  tools/objtool/check.c            |   2 +-
>  6 files changed, 193 insertions(+), 27 deletions(-)
>
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index abf3ad2e784e8..6446887cd1c92 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -192,6 +192,49 @@ Normally the shared buffer is used as follows::
>      up to the buffer[0] value saved above    |
>
>
> +Unique coverage collection
> +---------------------------
> +
> +Instead of collecting a trace of PCs, KCOV can deduplicate them on the fly.
> +This mode is enabled by the ``KCOV_UNIQUE_ENABLE`` ioctl (only available if
> +``CONFIG_KCOV_UNIQUE`` is on).
> +
> +.. code-block:: c
> +
> +       /* Same includes and defines as above. */
> +       #define KCOV_UNIQUE_ENABLE              _IOW('c', 103, unsigned long)
> +       #define BITMAP_SIZE                     (4<<10)
> +
> +       /* Instead of KCOV_ENABLE, enable unique coverage collection. */
> +       if (ioctl(fd, KCOV_UNIQUE_ENABLE, BITMAP_SIZE))
> +               perror("ioctl"), exit(1);
> +       /* Reset the coverage from the tail of the ioctl() call. */
> +       __atomic_store_n(&cover[BITMAP_SIZE], 0, __ATOMIC_RELAXED);
> +       memset(cover, 0, BITMAP_SIZE * sizeof(unsigned long));
> +
> +       /* Call the target syscall call. */
> +       /* ... */
> +
> +       /* Read the number of collected PCs. */
> +       n = __atomic_load_n(&cover[BITMAP_SIZE], __ATOMIC_RELAXED);
> +       /* Disable the coverage collection. */
> +       if (ioctl(fd, KCOV_DISABLE, 0))
> +               perror("ioctl"), exit(1);
> +
> +Calling ``ioctl(fd, KCOV_UNIQUE_ENABLE, bitmap_size)`` carves out ``bitmap_size``
> +unsigned long's from those allocated by ``KCOV_INIT_TRACE`` to keep an opaque
> +bitmap that prevents the kernel from storing the same PC twice. The remaining
> +part of the buffer is used to collect PCs, like in other modes (this part must
> +contain at least two unsigned long's, like when collecting non-unique PCs).
> +
> +The mapping between a PC and its position in the bitmap is persistent during the
> +kernel lifetime, so it is possible for the callers to directly use the bitmap
> +contents as a coverage signal (like when fuzzing userspace with AFL).
> +
> +In order to reset the coverage between the runs, the user needs to rewind the
> +trace (by writing 0 into the first buffer element past ``bitmap_size``) and zero
> +the whole bitmap.
> +
>  Comparison operands collection
>  ------------------------------
>
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index 2acccfa5ae9af..cea2e62723ef9 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -10,6 +10,7 @@ struct task_struct;
>  #ifdef CONFIG_KCOV
>
>  enum kcov_mode {
> +       KCOV_MODE_INVALID = -1,
>         /* Coverage collection is not enabled yet. */
>         KCOV_MODE_DISABLED = 0,
>         /* KCOV was initialized, but tracing mode hasn't been chosen yet. */
> @@ -23,6 +24,7 @@ enum kcov_mode {
>         KCOV_MODE_TRACE_CMP = 3,
>         /* The process owns a KCOV remote reference. */
>         KCOV_MODE_REMOTE = 4,
> +       KCOV_MODE_UNIQUE_PC = 5,
>  };
>
>  #define KCOV_IN_CTXSW  (1 << 30)
> diff --git a/include/linux/kcov_types.h b/include/linux/kcov_types.h
> index 9d38a2020b099..8be930f47cd78 100644
> --- a/include/linux/kcov_types.h
> +++ b/include/linux/kcov_types.h
> @@ -18,6 +18,14 @@ struct kcov_state {
>         /* Buffer for coverage collection, shared with the userspace. */
>         unsigned long *trace;
>
> +       /* Size of the bitmap (in bits). */
> +       unsigned int bitmap_size;
> +       /*
> +        * Bitmap for coverage deduplication, shared with the
> +        * userspace.
> +        */
> +       unsigned long *bitmap;
> +
>         /*
>          * KCOV sequence number: incremented each time kcov is reenabled, used
>          * by kcov_remote_stop(), see the comment there.
> diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
> index ed95dba9fa37e..e743ee011eeca 100644
> --- a/include/uapi/linux/kcov.h
> +++ b/include/uapi/linux/kcov.h
> @@ -22,6 +22,7 @@ struct kcov_remote_arg {
>  #define KCOV_ENABLE                    _IO('c', 100)
>  #define KCOV_DISABLE                   _IO('c', 101)
>  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kcov_remote_arg)
> +#define KCOV_UNIQUE_ENABLE             _IOW('c', 103, unsigned long)
>
>  enum {
>         /*
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 2005fc7f578ee..a92c848d17bce 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -28,6 +28,10 @@
>  #include <linux/log2.h>
>  #include <asm/setup.h>
>
> +#ifdef CONFIG_KCOV_UNIQUE
> +atomic_t kcov_guard_max_index = ATOMIC_INIT(0);
> +#endif
> +
>  #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
>
>  /* Number of 64-bit words written per one comparison: */
> @@ -163,9 +167,9 @@ static __always_inline bool in_softirq_really(void)
>         return in_serving_softirq() && !in_hardirq() && !in_nmi();
>  }
>
> -static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
> +static notrace enum kcov_mode get_kcov_mode(struct task_struct *t)
>  {
> -       unsigned int mode;
> +       enum kcov_mode mode;
>
>         /*
>          * We are interested in code coverage as a function of a syscall inputs,
> @@ -173,7 +177,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
>          * coverage collection section in a softirq.
>          */
>         if (!in_task() && !(in_softirq_really() && t->kcov_softirq))
> -               return false;
> +               return KCOV_MODE_INVALID;
>         mode = READ_ONCE(t->kcov_mode);
>         /*
>          * There is some code that runs in interrupts but for which
> @@ -183,7 +187,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
>          * kcov_start().
>          */
>         barrier();
> -       return mode == needed_mode;
> +       return mode;
>  }
>
>  static notrace unsigned long canonicalize_ip(unsigned long ip)
> @@ -202,7 +206,7 @@ static notrace void kcov_append_to_buffer(unsigned long *trace, int size,
>
>         if (likely(pos < size)) {
>                 /*
> -                * Some early interrupt code could bypass check_kcov_mode() check
> +                * Some early interrupt code could bypass get_kcov_mode() check
>                  * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
>                  * raised between writing pc and updating pos, the pc could be
>                  * overitten by the recursive __sanitizer_cov_trace_pc().
> @@ -219,14 +223,76 @@ static notrace void kcov_append_to_buffer(unsigned long *trace, int size,
>   * This is called once per basic-block/edge.
>   */
>  #ifdef CONFIG_KCOV_UNIQUE
> +DEFINE_PER_CPU(u32, saved_index);
> +/*
> + * Assign an index to a guard variable that does not have one yet.
> + * For an unlikely case of a race with another task executing the same basic
> + * block for the first time with kcov enabled, we store the unused index in a
> + * per-cpu variable.
> + * In an even less likely case of the current task losing the race and getting
> + * rescheduled onto a CPU that already has a saved index, the index is
> + * discarded. This will result in an unused hole in the bitmap, but such events
> + * should have minor impact on the overall memory consumption.
> + */
> +static __always_inline u32 init_pc_guard(u32 *guard)
> +{
> +       /* If the current CPU has a saved free index, use it. */
> +       u32 index = this_cpu_xchg(saved_index, 0);
> +       u32 old_guard;
> +
> +       if (likely(!index))
> +               /*
> +                * Allocate a new index. No overflow is possible, because 2**32
> +                * unique basic blocks will take more space than the max size
> +                * of the kernel text segment.
> +                */
> +               index = atomic_inc_return(&kcov_guard_max_index);
> +
> +       /*
> +        * Make sure another task is not initializing the same guard
> +        * concurrently.
> +        */
> +       old_guard = cmpxchg(guard, 0, index);
> +       if (unlikely(old_guard)) {
> +               /* We lost the race, save the index for future use. */
> +               this_cpu_write(saved_index, index);
> +               return old_guard;
> +       }
> +       return index;
> +}
> +
>  void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
>  {
> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> -               return;
> +       enum kcov_mode mode = get_kcov_mode(current);
> +       u32 pc_index;
>
> -       kcov_append_to_buffer(current->kcov_state.trace,
> -                             current->kcov_state.trace_size,
> -                             canonicalize_ip(_RET_IP_));
> +       switch (mode) {
> +       case KCOV_MODE_UNIQUE_PC:
> +               pc_index = READ_ONCE(*guard);
> +               if (unlikely(!pc_index))
> +                       pc_index = init_pc_guard(guard);
> +
> +               /*
> +                * Use the bitmap for coverage deduplication. We assume both
> +                * s.bitmap and s.trace are non-NULL.
> +                */
> +               if (likely(pc_index < current->kcov_state.bitmap_size))
> +                       if (__test_and_set_bit(pc_index,
> +                                              current->kcov_state.bitmap))
> +                               return;
> +               /*
> +                * If the PC is new, or the bitmap is too small, write PC to the
> +                * trace.
> +                */
> +               fallthrough;
> +       case KCOV_MODE_TRACE_PC:
> +               kcov_append_to_buffer(current->kcov_state.trace,
> +                                     current->kcov_state.trace_size,
> +                                     canonicalize_ip(_RET_IP_));
> +               break;
> +       default:
> +               return;
> +       }
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
>
> @@ -238,7 +304,7 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard_init);
>  #else /* !CONFIG_KCOV_UNIQUE */
>  void notrace __sanitizer_cov_trace_pc(void)
>  {
> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> +       if (get_kcov_mode(current) != KCOV_MODE_TRACE_PC)
>                 return;
>
>         kcov_append_to_buffer(current->kcov_state.trace,
> @@ -256,7 +322,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>         u64 *trace;
>
>         t = current;
> -       if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
> +       if (get_kcov_mode(t) != KCOV_MODE_TRACE_CMP)
>                 return;
>
>         ip = canonicalize_ip(ip);
> @@ -374,7 +440,7 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
>         t->kcov = kcov;
>         /* Cache in task struct for performance. */
>         t->kcov_state = *state;
> -       /* See comment in check_kcov_mode(). */
> +       /* See comment in get_kcov_mode(). */
>         barrier();
>         WRITE_ONCE(t->kcov_mode, mode);
>  }
> @@ -409,6 +475,10 @@ static void kcov_reset(struct kcov *kcov)
>         kcov->mode = KCOV_MODE_INIT;
>         kcov->remote = false;
>         kcov->remote_size = 0;
> +       kcov->state.trace = kcov->state.area;
> +       kcov->state.trace_size = kcov->state.size;
> +       kcov->state.bitmap = NULL;
> +       kcov->state.bitmap_size = 0;
>         kcov->state.sequence++;
>  }
>
> @@ -549,18 +619,23 @@ static int kcov_close(struct inode *inode, struct file *filep)
>         return 0;
>  }
>
> -static int kcov_get_mode(unsigned long arg)
> +static enum kcov_mode kcov_arg_to_mode(unsigned long arg, int *error)
>  {
> -       if (arg == KCOV_TRACE_PC)
> +       if (arg == KCOV_TRACE_PC) {
>                 return KCOV_MODE_TRACE_PC;
> -       else if (arg == KCOV_TRACE_CMP)
> +       } else if (arg == KCOV_TRACE_CMP) {
>  #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
>                 return KCOV_MODE_TRACE_CMP;
>  #else
> -               return -ENOTSUPP;
> +               if (error)
> +                       *error = -ENOTSUPP;
> +               return KCOV_MODE_INVALID;
>  #endif
> -       else
> -               return -EINVAL;
> +       } else {
> +               if (error)
> +                       *error = -EINVAL;
> +               return KCOV_MODE_INVALID;
> +       }
>  }
>
>  /*
> @@ -595,12 +670,47 @@ static inline bool kcov_check_handle(u64 handle, bool common_valid,
>         return false;
>  }
>
> +static long kcov_handle_unique_enable(struct kcov *kcov,
> +                                     unsigned long bitmap_words)
> +{
> +       struct task_struct *t = current;
> +
> +       if (!IS_ENABLED(CONFIG_KCOV_UNIQUE))
> +               return -ENOTSUPP;
> +       if (kcov->mode != KCOV_MODE_INIT || !kcov->state.area)
> +               return -EINVAL;
> +       if (kcov->t != NULL || t->kcov != NULL)
> +               return -EBUSY;
> +
> +       /*
> +        * Cannot use zero-sized bitmap, also the bitmap must leave at least two
> +        * words for the trace.
> +        */
> +       if ((!bitmap_words) || (bitmap_words >= (kcov->state.size - 1)))
> +               return -EINVAL;
> +
> +       kcov->state.bitmap_size = bitmap_words * sizeof(unsigned long) * 8;
> +       kcov->state.bitmap = kcov->state.area;
> +       kcov->state.trace_size = kcov->state.size - bitmap_words;
> +       kcov->state.trace = ((unsigned long *)kcov->state.area + bitmap_words);
> +
> +       kcov_fault_in_area(kcov);
> +       kcov->mode = KCOV_MODE_UNIQUE_PC;
> +       kcov_start(t, kcov, kcov->mode, &kcov->state);
> +       kcov->t = t;
> +       /* Put either in kcov_task_exit() or in KCOV_DISABLE. */
> +       kcov_get(kcov);
> +
> +       return 0;
> +}
> +
>  static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                              unsigned long arg)
>  {
>         struct task_struct *t;
>         unsigned long flags, unused;
> -       int mode, i;
> +       enum kcov_mode mode;
> +       int error = 0, i;
>         struct kcov_remote_arg *remote_arg;
>         struct kcov_remote *remote;
>
> @@ -618,9 +728,9 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 t = current;
>                 if (kcov->t != NULL || t->kcov != NULL)
>                         return -EBUSY;
> -               mode = kcov_get_mode(arg);
> -               if (mode < 0)
> -                       return mode;
> +               mode = kcov_arg_to_mode(arg, &error);
> +               if (mode == KCOV_MODE_INVALID)
> +                       return error;
>                 kcov_fault_in_area(kcov);
>                 kcov->mode = mode;
>                 kcov_start(t, kcov, mode, &kcov->state);
> @@ -628,6 +738,8 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 /* Put either in kcov_task_exit() or in KCOV_DISABLE. */
>                 kcov_get(kcov);
>                 return 0;
> +       case KCOV_UNIQUE_ENABLE:
> +               return kcov_handle_unique_enable(kcov, arg);
>         case KCOV_DISABLE:
>                 /* Disable coverage for the current task. */
>                 unused = arg;
> @@ -646,9 +758,9 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 if (kcov->t != NULL || t->kcov != NULL)
>                         return -EBUSY;
>                 remote_arg = (struct kcov_remote_arg *)arg;
> -               mode = kcov_get_mode(remote_arg->trace_mode);
> -               if (mode < 0)
> -                       return mode;
> +               mode = kcov_arg_to_mode(remote_arg->trace_mode, &error);
> +               if (mode == KCOV_MODE_INVALID)
> +                       return error;
>                 if ((unsigned long)remote_arg->area_size >
>                     LONG_MAX / sizeof(unsigned long))
>                         return -EINVAL;
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index 60eb5faa27d28..f4ec041de0224 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -1154,7 +1154,7 @@ static const char *uaccess_safe_builtin[] = {
>         "__tsan_unaligned_write16",
>         /* KCOV */
>         "write_comp_data",
> -       "check_kcov_mode",
> +       "get_kcov_mode",
>         "__sanitizer_cov_trace_pc",
>         "__sanitizer_cov_trace_pc_guard",
>         "__sanitizer_cov_trace_const_cmp1",
> --
> 2.50.1.470.g6ba607880d-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYLMO8hE3GqnXpSjoCD%3DPbFjGNWcKSN0BH10ASMHkHN8A%40mail.gmail.com.
