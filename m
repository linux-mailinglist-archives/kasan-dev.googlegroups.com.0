Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG6HWO4QMGQEX45KXOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 42DF89C0A90
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 16:58:21 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5eb5bfc32ccsf915287eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 07:58:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730995100; cv=pass;
        d=google.com; s=arc-20240605;
        b=GmIHLz3X7QWLaCpf+8AyqAf7M0ojlnQQ8ViCuFoRf4xclKikthZtfkIjQnBK5x79ml
         eR4czg4RpcfQxDhSRzarc0ItwuoZGyy85242822KXMlLGLlQy3WHLYLpZGjTOy2imOaL
         ezHZZOOBAgDZU8wb2iuVEg1yVCA2s9hIgs9d0naJFawQf9l8dI4XgmW1gwQVEEpFuJNA
         kjsTwxnzy+OdsaZDF9HtxQH+YueEn+RdmAI+ydh4GTTK9RaKn3YlqVDxslhlN9F7M6LU
         TNXG/eLVvxtHLfsUlrKZc1mN1rUIVN0n56D+FVneMGu0AxCjtnC21VBQC24f8SouRTO/
         3c4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cGnM2wLbyPXlzVEOpfgzPSTa4Dx8cxfLVVb4cocoQ2s=;
        fh=oIIk7NkdW+JDOO987hsWdxfxeVlUpiPTuQnxJrb6gzM=;
        b=kbBdZX0Pn+3HL77ATXvb57P+opnDPBHyBV9a+MXpPl3tF/BdwzshoAs8L0tk6SP9rt
         DaL+QXpIHRjyb/nIA7HDkVpzPKtdISAmnyB43jzwhp/Smvua0AKxFbbdCKxzMBjOf7Bl
         xL0uxo3g2AdEr8i2s9OM9gZclgIuTQx3Tx1Jvajov7AnZBjFwsabDPqyrF1YyIYQyo1H
         iI/LO+CC/9bW/RZwSbkDvXeKO37lJgR5s7H1lS3fsxPVbJb4Ejk3oZ2NvFk44RkGpTw9
         +nkbZgBgUxoeWqtt1sKOvxyNGeFstogVTGOZHL8AKZw9o9kubMd6GGPOGjT8WwYpE26J
         O6HA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rhBpjyj5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730995100; x=1731599900; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cGnM2wLbyPXlzVEOpfgzPSTa4Dx8cxfLVVb4cocoQ2s=;
        b=GzA4vyYCu6XYPBIg6jVBcLBaYUu8Uxyqw9yGKHWx1WMinkJSAIkWf7GV9RB9C7iXV1
         X2SXe++OL7AeEQfMEeiK4lN4Qnbs5yaOwGGjRl8v0mRctgJ3U3U7dzuDvo+pbOuE3Ik3
         1XY8P/X6M4Ln4CD1OhYrjQ+BIcFuYQlvWBFeJU+3xGi/YHZGOzAl8jk71trBFdebA+cf
         gzAlTIqBejRWsHNi62BiKl3AM5DHIw6/YHn7FYKhnB5SP9b0vFp42RYfNi2Dk0u4IV9q
         xn6x7+rGkzVAEEB8g8SJELpQWq+3yDgXrE9i9vM+8uzRdFVSGhHi1umbsXcOu6fSigoC
         3Jzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730995100; x=1731599900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cGnM2wLbyPXlzVEOpfgzPSTa4Dx8cxfLVVb4cocoQ2s=;
        b=fMznmFyDCb53Tmbvlj0Uvabg8K8rjhYAFM7fym0rL9/qwg+ryHDEPhzi0VqkKTdhnl
         y2Dg9NFI6N5j/JViI7Xkk8lw6rZ1mKeUsAoxXz6ZZY72lQBaP+08g8ZfFtyCLTgwcC4H
         NtcOeDbIXzkZU2E46qC0kPTobknu0A18scZK9IjJMPx8nxlU6BOXTSmvo8eDZ8z4jUnV
         cYg3z3UtARryBeRcfGoLv6njlfqrdZte8wQlahvblnZdGd29q5gKiNWylX9jXcFirJNT
         qjEcZ/JjtVmTCBVp1Efll4s2tb5JBT74w1rmnFim8jfS8oVf/tiepGeAVMrr1kOTS/PU
         M/Ww==
X-Forwarded-Encrypted: i=2; AJvYcCUIMXIzSEq12XS8RCxFp3nBoAail8vRsEhZU5yHORmK1rjXZi6OoloiWxclrAzOMh66n2tu5w==@lfdr.de
X-Gm-Message-State: AOJu0YyyuTAFFsvZIjaGlYOGCJN/qMLet2LKJ6Ew/pb84DQqnuogzgS3
	HmIlRNynECUmDBnmyHWP+nB+U4TcQFCz7ZHbLCw0cS4xB3aoJIRb
X-Google-Smtp-Source: AGHT+IHevwbP/jLs5C6xjnkKVkVqJjsJhiHRrg508b4naM0GVeMWd7ZhtIypCxABSMTnH1hczrlruQ==
X-Received: by 2002:a4a:e90f:0:b0:5e3:b7a6:834 with SMTP id 006d021491bc7-5ee568d313amr42520eaf.1.1730995100061;
        Thu, 07 Nov 2024 07:58:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:2206:b0:5e7:b0e9:85d1 with SMTP id
 006d021491bc7-5ee45c97723ls993830eaf.2.-pod-prod-08-us; Thu, 07 Nov 2024
 07:58:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVuYZLPfdYyaK4NYOalt3zEt3WEr523PwqLvvOos6VBmDMv5hRH/v49HXF0+Kf7OypaTYb71AUfkec=@googlegroups.com
X-Received: by 2002:a05:6820:4b0a:b0:5e7:caf5:ae1f with SMTP id 006d021491bc7-5ee568d3115mr34822eaf.2.1730995097006;
        Thu, 07 Nov 2024 07:58:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730995096; cv=none;
        d=google.com; s=arc-20240605;
        b=UuL753/e9e81uQxncKFzoUmjgFTbbcKI81I4umEnj2meaeCoumbPDuoaS3j6KS5Lf+
         nPFHja/O1sjeFzFPWseetvLYcJJmrrRaSWYX8KUYqQdWO0DSUKyeQhGU9QMk8WlNTxxB
         fm56tQMB96EOE+3yAR10juWSrljgWUaMNYpOV08Oa3X6o8HkZah34iFHRqO82eIKfAB4
         jfn/WahTB/T40Yy61ToHHUXjDbGwp34WxeonOTLuZnqLfSo8YaCZDUo30O89PqhDUqsH
         HpMKOfAq0yrb7UWaqYQ6L7ahfbYqMBtjs7Ya2/z0J0uc93Enx3tQrUQKmzgnlHfbwRCq
         HeIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jyTQmFg5RkUDePP5hgukMfc9dpeVcrhVZzNqZ7P2B9g=;
        fh=EEblTbsn/+F2kgeceOEG4zWZxt5DiWXKCcFP7kmM/ic=;
        b=a8C52veSIfycQugSv2jlKa/Z5r15A/xsy0DMzGEpLVHSBxTViUK7gzQXS2MIe6OCbT
         z7ALjWHAIdX6kWGiDmpc41hv7B7GHxEw8VRZ6XNK8QP07K9cRjQSZwmJlFBsRGBPMbAi
         q6osm8vTao6UwuUqkwQ5Hp6Ohh9FfqexnOLMPhIwQfRH/kY6eg3nMrJWY3K5TP6sJ+i0
         anxAOXeDykeKplb3YjQIRV2UvD9TsEjm/2x1zLs7h3iudBQTJMZxE0Bnzn9r6YU97jWj
         N057SoCrhQyJZn5OZDhYBZnTegn/Rrwrte3/TC+erVCEDZW38Y0ewguscYLvTdE6wAG/
         J4Uw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rhBpjyj5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5ee493844f5si84888eaf.0.2024.11.07.07.58.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Nov 2024 07:58:16 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id 98e67ed59e1d1-2e34a089cd3so912315a91.3
        for <kasan-dev@googlegroups.com>; Thu, 07 Nov 2024 07:58:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVkB99+r9Ncgnk2hgLOwNFeEIA8N+tSy3D8hvH26fdhE15i0Xr2gqf/gJV9hLAe2pWKxis+D5nZsCE=@googlegroups.com
X-Received: by 2002:a17:90b:4c86:b0:2e2:c40c:6e8e with SMTP id
 98e67ed59e1d1-2e8f11b961fmr46812604a91.34.1730995096225; Thu, 07 Nov 2024
 07:58:16 -0800 (PST)
MIME-Version: 1.0
References: <20241107122648.2504368-1-elver@google.com> <5b7defe4-09db-491e-b2fb-3fb6379dc452@efficios.com>
 <CANpmjNPWLOfXBMYV0_Eon6NgKPyDorTxwS4b67ZKz7hyz5i13A@mail.gmail.com> <3326c8a1-36c7-476b-8afa-2957f5bd5426@efficios.com>
In-Reply-To: <3326c8a1-36c7-476b-8afa-2957f5bd5426@efficios.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Nov 2024 16:57:39 +0100
Message-ID: <CANpmjNMjd6p5-SMjNh6k1gqubvNew2fA5GDs1YmcSdiSFCA5pQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] tracing: Add task_prctl_unknown tracepoint
To: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Kees Cook <keescook@chromium.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Oleg Nesterov <oleg@redhat.com>, linux-kernel@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=rhBpjyj5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 7 Nov 2024 at 16:54, Mathieu Desnoyers
<mathieu.desnoyers@efficios.com> wrote:
>
> On 2024-11-07 10:46, Marco Elver wrote:
> > On Thu, 7 Nov 2024 at 16:45, Mathieu Desnoyers
> > <mathieu.desnoyers@efficios.com> wrote:
> >>
> >> On 2024-11-07 07:25, Marco Elver wrote:
> >>> prctl() is a complex syscall which multiplexes its functionality based
> >>> on a large set of PR_* options. Currently we count 64 such options. The
> >>> return value of unknown options is -EINVAL, and doesn't distinguish from
> >>> known options that were passed invalid args that also return -EINVAL.
> >>>
> >>> To understand if programs are attempting to use prctl() options not yet
> >>> available on the running kernel, provide the task_prctl_unknown
> >>> tracepoint.
> >>>
> >>> Note, this tracepoint is in an unlikely cold path, and would therefore
> >>> be suitable for continuous monitoring (e.g. via perf_event_open).
> >>>
> >>> While the above is likely the simplest usecase, additionally this
> >>> tracepoint can help unlock some testing scenarios (where probing
> >>> sys_enter or sys_exit causes undesirable performance overheads):
> >>>
> >>>     a. unprivileged triggering of a test module: test modules may register a
> >>>        probe to be called back on task_prctl_unknown, and pick a very large
> >>>        unknown prctl() option upon which they perform a test function for an
> >>>        unprivileged user;
> >>>
> >>>     b. unprivileged triggering of an eBPF program function: similar
> >>>        as idea (a).
> >>>
> >>> Example trace_pipe output:
> >>>
> >>>     test-484     [000] .....   631.748104: task_prctl_unknown: comm=test option=1234 arg2=101 arg3=102 arg4=103 arg5=104
> >>>
> >>
> >> My concern is that we start adding tons of special-case
> >> tracepoints to the implementation of system calls which
> >> are redundant with the sys_enter/exit tracepoints.
> >>
> >> Why favor this approach rather than hooking on sys_enter/exit ?
> >
> > It's __extremely__ expensive when deployed at scale. See note in
> > commit description above.
>
> I suspect you base the overhead analysis on the x86-64 implementation
> of sys_enter/exit tracepoint and especially the overhead caused by
> the SYSCALL_WORK_SYSCALL_TRACEPOINT thread flag, am I correct ?
>
> If that is causing a too large overhead, we should investigate if
> those can be improved instead of adding tracepoints in the
> implementation of system calls.

Doing that may be generally useful, but even if you improve it
somehow, there's always some additional bit of work needed on
sys_enter/exit as soon as a tracepoint is attached. Even if that's
just a few cycles, it's too much (for me at least).

Also: if you just hook sys_enter/exit, you don't know if the prctl was
handled or not by inspecting the return code (-EINVAL). I want the
kernel to tell me if it handled the prctl() or not, and I also think
it's very bad design to copy-paste the prctl() option checking of the
running kernel in a sys_enter/exit hook. This doesn't scale in terms
of performance nor maintainability.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMjd6p5-SMjNh6k1gqubvNew2fA5GDs1YmcSdiSFCA5pQ%40mail.gmail.com.
