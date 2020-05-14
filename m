Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQUF632QKGQEF26S52Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 74A6B1D3882
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 19:41:23 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id r18sf4261009ybg.10
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 10:41:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589478082; cv=pass;
        d=google.com; s=arc-20160816;
        b=XuxGUnozZVKMyiJHFNrF339ZrGhfZwoJup462kU+UVkv83XnYfyhl+YxAvkttPYfT5
         zgt/kofSAnisgoG1UU94AEgMkv4tC+QVxluY7a0OtDT+38EHYSGmpW3tuo07sF3Ob9tn
         grm6lXiaxwIx2S27Se/bhek3kdFrKjfihAbRvxj6FX2NRHZFt+SLjmsnzOVjRLQ6/ijm
         hfRG3j3/bWyncaV2mLQNCRIa6+IZs7V+lng5ZvYRRcKtbZo5pOhAoZcClrIyzsPsNbPX
         xCLEr/t93ARJTPaEdAF4RBcsxYO+ZWWEGRORfzy4t80cJfPtsUFLqqDD92L4tSyim2PF
         9EFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:subject:message-id:date
         :from:mime-version:dkim-signature;
        bh=ViMzwApxmGcFqpFNEKPoqROco5VCs71M1bAet5SMwkc=;
        b=sv0brz/xXNY/GpJwBjnTgYCOtKM+UPz6841dz+LNDdTa6m0CSybRF13qU1mA/dLX57
         n41mxi9tr+Ea+4olDHnk9TMvnHf9tVHWQbnc7nZKegTAcKFAXGupjTU+dm4E4MuW8EC6
         wH6frYOwGetF2jtJ/hy6lU00bgWE3MoNXwj1xsYrWtfwPqBX6UMb+2LIQ7F8Dks7VOL6
         8tnB1/VDNa61QktxUUtYYy0nQ1dFQxGAy7ZJdbily2mZvdDaIr/3Zx+yi5mE5Up1b8z9
         YdLBXn0toUhAT8rixvjV9SPbNzVbB1EQ5nfO6+lqPBDTQhpodGvUjeYMgkUqHHRbSg5j
         yqdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CyrUbM07;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ViMzwApxmGcFqpFNEKPoqROco5VCs71M1bAet5SMwkc=;
        b=AvQq5c2On6/5yMwuqDsIugaSSPr1phX1HbW6gcesHrCwnXo6EebzuOWer8Mj7q2JG6
         DD2Sw2UPO9rdH9OiqvOK78XkMK13pFcSVAw+VF7jJSH86a/RWPSZ40CYwsifWCmYd8A4
         r/TUeqUoFAn0stWClc4I8gHVV7qOF2EZcXfXumV8bGL6hu9JnBwzZ1pJoL1pzsB1sGoA
         5EpHhiiEv6fxzfwD6Bfo2Xkfj5KzButG1RW/Jy5vkN9nVmqS+4HzaRq25GgXVI8rClvX
         Z7gxP4zkkemsa/OdQcim56AcKQMEXQY0kgZiTSQL51lSuN1su0fgY/cfuxRfcNwgJbrw
         jnBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ViMzwApxmGcFqpFNEKPoqROco5VCs71M1bAet5SMwkc=;
        b=njIO5tb9Ts/H+/1wN5zZ9owGw8vn2TU68gJ/wKavZ3b2iZQzQkqEMkFTeR5ElUQTts
         LDwU6CGpEjqMdjoqxSsF3mlw+0Qnfvh29QouQNGww6Qb9mL9kFeB61FMs3FgQZeBKhDm
         WZxRksV5B4yVWejYQi2fgU9eVf+8qEoiNnmJop9HyMPJNpVFp3B9OYdg3ndKkEyLEfNr
         KZqntRURlU+txQZyqRhsrp62uB2vrxDuB7KCvWW7TsUZYdMHmFAdl3CN8FXg0oUM1AeY
         rui7w5ZJIKYCgaTK1TpkDDLC45urMo3vHUpLWBNaQ16FX5erS60RcXVRGK+Hc8NIgsIw
         Wu6A==
X-Gm-Message-State: AOAM533cyGwtndPSEAX99e14gYGMRL5ql2LAeFrER8MyVOxcNKsMd0BY
	/qYF9/1VZ/L6YNIYmqsccrU=
X-Google-Smtp-Source: ABdhPJyNem9oZr/WFFNq1t55JrZljeihK9K17EOPPisDq7iDwNGg/imMImcOVw4F9WC1jLmBsH3TqA==
X-Received: by 2002:a25:5387:: with SMTP id h129mr8651356ybb.413.1589478082493;
        Thu, 14 May 2020 10:41:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3897:: with SMTP id f145ls1478812yba.9.gmail; Thu, 14
 May 2020 10:41:22 -0700 (PDT)
X-Received: by 2002:a25:858e:: with SMTP id x14mr9731407ybk.457.1589478082020;
        Thu, 14 May 2020 10:41:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589478082; cv=none;
        d=google.com; s=arc-20160816;
        b=o7DBvHFNxCBCgkSN1uv4ql2OPrND9Rc7CaOHOtAw11EhIwNHjQcMDw5j9kkND4q+fw
         Ygn4/5FyxRR+1PjllirSI3x1zsVAjNILMfVhMPjWrju1Q+QAxwZwJyFTfPdisn5iyLnk
         XbtLcsI3rKTXug2XCqqtf5m0DtwtmbF39ys8a3TPfwr/G61ZCIsjQMQQx6yKfRvdMZ8C
         M5mBfcm2Il9STpTwtok9jpEm3FFAf2mZmStB4OA0bV0yvWLU9lUI/RucFGzUL0MUS4i8
         riI6dUKYjbLV0G+Gr7an7QUOKQIMXG5yk42SB31qhiC07plNDWn4D4RJC/CptdkFQEWB
         +A/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=ya52B8W254Qs4dRwJLWq3FqzUBXxL/RTpbEftDe0Ep4=;
        b=fWnnyTzEVIY5Q7e1aD4O22/7qDv07jTYUYolskrQKY2NpUXw29REXPkCppJHMWNpX9
         eWgaog6l+NSaSbRD4Lq+z/HHeISvkw4YtBLPgl/tM2aQjee7EXadeF9jKUDurJDUqPth
         9Js3dcOglw2CDVZQeuyQCpUVTNp/lCDAgTAnhtSIH4CVsDyh+d8YDKYVCSxpn5usw7f6
         Zerd6vdfxpFUHxm4/LqtTCrSQLBlfL3oqh4rWllqdlsBCxzbaw7mkc2dQfvSatuGozb6
         2QlrQtu3mmQlyElxbcwn6eRxfRqahiUqAgaHZDRHBhOmkPUamNAXwkKt5gAMYHxsSmf8
         8jtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CyrUbM07;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x336.google.com (mail-ot1-x336.google.com. [2607:f8b0:4864:20::336])
        by gmr-mx.google.com with ESMTPS id m9si270226ybc.3.2020.05.14.10.41.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 May 2020 10:41:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) client-ip=2607:f8b0:4864:20::336;
Received: by mail-ot1-x336.google.com with SMTP id j4so3011756otr.11
        for <kasan-dev@googlegroups.com>; Thu, 14 May 2020 10:41:21 -0700 (PDT)
X-Received: by 2002:a9d:68c5:: with SMTP id i5mr4076012oto.251.1589478081354;
 Thu, 14 May 2020 10:41:21 -0700 (PDT)
MIME-Version: 1.0
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 May 2020 19:41:10 +0200
Message-ID: <CANpmjNNLY9EcSXhBbdjMR2pLJfrgQoffuzs27Xrgx3nOuAUxMQ@mail.gmail.com>
Subject: ORC unwinder with Clang
To: clang-built-linux <clang-built-linux@googlegroups.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CyrUbM07;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

Hi,

Is CONFIG_UNWINDER_ORC=y fully supported with Clang?

I'm seeing frames dropped in stack-traces with
stack_trace_{dump,print}. Before I dig further, the way I noticed this
is when running the KCSAN test (in linux-next):

CONFIG_KCSAN=y
CONFIG_KCSAN_TEST=y

The test-cases "test_assert_exclusive_access_writer" for example fail
because the frame of the function that did the actual access is not in
the stack-trace.

When I use __attribute__((disable_tail_calls)) on the functions that
do not show up in the stack traces, the problem goes away. Obviously
we don't want to generally disable tail-calls, but it highlights an
issue with the ORC unwinder and Clang.

Is this a known issue? Any way to fix this?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNLY9EcSXhBbdjMR2pLJfrgQoffuzs27Xrgx3nOuAUxMQ%40mail.gmail.com.
