Return-Path: <kasan-dev+bncBCT6537ZTEKRBY4CVL7AKGQE7NFSC4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id C8BDA2CF421
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 19:35:15 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id bm18sf2382995ejb.6
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 10:35:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607106915; cv=pass;
        d=google.com; s=arc-20160816;
        b=lwfdZw47XLeU1B4lx+/fNAsOPteI7a3hisVq7dJkQ7CJVqu/vqU8dCOOPpQSlxyuTE
         X0rzMuEZvNGv+/PsDjlbFQaUuGcyWDg2mTiXW8R15QTVwttVqNd82IJpssVX2XjEiv5b
         emD5o6jcxGS3UYBq4/4vSwAsLk82IvD98StyL2kbIehuIsFqtWFQpZXhbb8a0xc1jQPd
         EYbtsyF7OXUxNJO/gsx2hnA0MVPayUOUJTCYlZtBVOm6NJm+ft/svGaXCpGjymt7IZdg
         SBedKXiLgTZ8X0oq4MP7WqRMYh4rtNi2uHofZfyzpqWE5iH0rCFVreQT9sR7zo10hB7n
         sF8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=/+wm8LhTmYuSPTLVdxrSdSyxAhE0TSMq6vaYHqzPscU=;
        b=yBgIfX96Di9TrSQHCeX8tXqfpTLUzfDTrAlJRBCRDErQshmCDasNw+we115wmwQKM2
         +Au8YEkmy3mYwaTB9ZlPtWdHabjbgDCl+qcMIyiAf6TcQRsuWnX9evd7b/iqt00JvaBh
         2FXKbWZo1lb4X1RN0vHMp1+dqDYfLKe96gQdtVUAD3/mxiAHv2vLF5l2Hu3zHBOn5lAJ
         cSgX97lrTmyndDB98IXcQKWjlUusVf0WDsUriAl0VeWCcWxL1vBjvhgqT5VwYDP3M+hj
         TKEX+VxEyFXeP09cg+Usuy48bJNwowHGZWYYZ/jaZanH+fmMeOWspfdA3OXUDLLIGgRB
         NmNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=UoAtycuW;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/+wm8LhTmYuSPTLVdxrSdSyxAhE0TSMq6vaYHqzPscU=;
        b=U3rQgeC4CVZamBuAD6vl7b5nniOJlqW8My2k/sV8HV6Tz6qWdG7/4BDKW7RhNn1nnO
         LGLuLU9PoPa5fCyz04ps//h92MXs3c6tVrVC4N1+Faoj3i/3Sq8JB0mXvV12XOs03IBm
         Sr9RaHxn0HDowGWtz3RdLgkybibSR2WZ2nQpAptGLqoa3zdU54GAPNmLTWGi/N4Uos0J
         vFXC6BE6ntOS6GNtQ8pvkviqnmY/kLyWEmpP9ZNnB6Uvbc77tcl/tvEhSatblrA0+xwV
         4/KSVYo8f3N9k/CyYI7aejZuXAJ6e2eig9+L9nGw089HAGkB2f3Zs7tdfv3DxQfqxO0u
         YZ8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/+wm8LhTmYuSPTLVdxrSdSyxAhE0TSMq6vaYHqzPscU=;
        b=eGaO8+ib4gefqst0QclFGuB36jeyJipfP0sjquZbura0P8uC6Yy7lREWW521P28aEL
         /SId3Gm4ZEnTwQzqkptwWJZkNyoi4K1FstPYb59NJ0Emfhn4ThhLRUl2g5OPKNEoR4rO
         mRXf9iZSt/YBuTN2KdJZrvJWdeeVSj/6SQdhFJK/MpH6lMaGw/VjttCkp8eva+jzEor5
         LLxS2r5Q7lp0ps/RIm44vfFaiSQ5KXhRhbDAbEDrg6zVK2po9GgaQeSb6+GmTbzF6sqL
         80N2kWaj8ohxkbS0BgwwDHHG7IDgFmwje8R07qiGx0OLBpUsQrSa07lVkwP9pULqsAbp
         mb0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533IroW/6MmGrG//rP6py1WEaI8bLRVGJdsCtskCpwt27cIRed9H
	P/8YTx0eKu5Dr/bqV+Q7k6U=
X-Google-Smtp-Source: ABdhPJwGxKf+GWkI3jHPvN0JrX+H8gc7XbCRc+Gyp17zLNUNYjUV7i0ZYqfOSeIox9EO/9Uu7YhLqQ==
X-Received: by 2002:a50:9ee6:: with SMTP id a93mr9057890edf.174.1607106915562;
        Fri, 04 Dec 2020 10:35:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:22d3:: with SMTP id dm19ls6058671edb.2.gmail; Fri,
 04 Dec 2020 10:35:14 -0800 (PST)
X-Received: by 2002:a50:f1c7:: with SMTP id y7mr8984447edl.184.1607106914677;
        Fri, 04 Dec 2020 10:35:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607106914; cv=none;
        d=google.com; s=arc-20160816;
        b=lkuwHDqCQ4CaEVOM5MQPGgrh0GD+ylQZuUiXQtfijm/qfI1uy9CprrYnjVC7clEkzk
         LT3rndOvrijrXZGOwhWXZwS/eDZjoPHMLejqpJDmQPob3terkpiNFF6aUexbVN/Te+x5
         TnpKg57sjkX6kPVO5W6shx9DHhjNOSPF1l2ZiHm/DWSIYy2sDXQBAa0DjVeUfoIyIYKc
         x2VKSagyCkCfIcFHmXtTlAGTCmXqEnVqJU0ZufLc5nFY5RL18eKXB/2iraBQDHBkTK48
         bvLUpDvGa5kYNi4IYbeM2NisIlSJNrgvRe4jOZL2LuGn/JtLOega6Aon8haOC0+61SWZ
         9gnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=VazwCTbw4qFEcnDS99kE7+UPTpKgFLvwXrTcJ/OGLV8=;
        b=0d3/u8z/XNeLNmV3S93kMGFGbb7kmoj4H5+7unFbryaF2f1zY9VHQ0oFou9J2OypVu
         SlvhnJ7A782UcFI6IxNeN+ui9Z8UBr/bW05EId12GhXc03oJDAzKZAr1LPvcX904CXtM
         VxL2Xy/WkuVL26cXUQe3NTavkXVb7bC4pnTdXvqI9/ROmETRGCTE7R9hbR85uhVV7voj
         fKMJU6fX/D7TSOMP6jbX8cV2Nc1SMF1KJcz9bplN5o9gflIq22iafMW5NZ6OF1kUAHQS
         bwLCcQtAb7qj+xQXv8R6UchZ7TuBluIrQz439dYzNrTXrAbYS1G6V9Spc+CcnujiqX7q
         mreg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=UoAtycuW;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id v7si361967edj.5.2020.12.04.10.35.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 10:35:14 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id q16so6822353edv.10
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 10:35:14 -0800 (PST)
X-Received: by 2002:aa7:d74d:: with SMTP id a13mr5352244eds.78.1607106913506;
 Fri, 04 Dec 2020 10:35:13 -0800 (PST)
MIME-Version: 1.0
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Sat, 5 Dec 2020 00:05:02 +0530
Message-ID: <CA+G9fYvhvZtDYVBo4kj9OkKY_vVFSa6EbWz99iCmRPojExRieA@mail.gmail.com>
Subject: BUG: KCSAN: data-race in __rpc_do_wake_up_task_on_wq / xprt_request_transmit
To: kasan-dev <kasan-dev@googlegroups.com>, open list <linux-kernel@vger.kernel.org>, 
	Netdev <netdev@vger.kernel.org>, linux-nfs@vger.kernel.org, 
	lkft-triage@lists.linaro.org, rcu@vger.kernel.org
Cc: Jakub Kicinski <kuba@kernel.org>, "David S. Miller" <davem@davemloft.net>, chuck.lever@oracle.com, 
	bfields@fieldses.org, anna.schumaker@netapp.com, 
	trond.myklebust@hammerspace.com, "Paul E. McKenney" <paulmck@kernel.org>, 
	Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=UoAtycuW;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
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

LKFT started testing KCSAN enabled kernel from the linux next tree.
Here we have found BUG: KCSAN: data-race in
__rpc_do_wake_up_task_on_wq / xprt_request_transmit

This report is from an x86_64 machine clang-11 linux next 20201201.
Since we are running for the first time we do not call this regression.

[   17.316725] BUG: KCSAN: data-race in __rpc_do_wake_up_task_on_wq /
xprt_request_transmit
[   17.324821]
[   17.326322] write to 0xffff90a801de6a9c of 2 bytes by task 142 on cpu 1:
[   17.333022]  __rpc_do_wake_up_task_on_wq+0x295/0x350
[   17.337987]  rpc_wake_up_queued_task+0x99/0xc0
[   17.342432]  xprt_complete_rqst+0xef/0x100
[   17.346533]  xs_read_stream+0x9c6/0xc40
[   17.350370]  xs_stream_data_receive+0x60/0x130
[   17.354819]  xs_stream_data_receive_workfn+0x5c/0x90
[   17.359784]  process_one_work+0x4a6/0x830
[   17.363795]  worker_thread+0x5f7/0xaa0
[   17.367548]  kthread+0x20b/0x220
[   17.370780]  ret_from_fork+0x22/0x30
[   17.374359]
[   17.375858] read to 0xffff90a801de6a9c of 2 bytes by task 249 on cpu 3:
[   17.382473]  xprt_request_transmit+0x389/0x7a0
[   17.386919]  xprt_transmit+0xfe/0x250
[   17.390583]  call_transmit+0x10d/0x120
[   17.394337]  __rpc_execute+0x12d/0x700
[   17.398089]  rpc_async_schedule+0x59/0x90
[   17.402100]  process_one_work+0x4a6/0x830
[   17.406114]  worker_thread+0x5f7/0xaa0
[   17.409868]  kthread+0x20b/0x220
[   17.413099]  ret_from_fork+0x22/0x30
[   17.416675]
[   17.418167] Reported by Kernel Concurrency Sanitizer on:
[   17.423475] CPU: 3 PID: 249 Comm: kworker/u8:1 Not tainted
5.10.0-rc6-next-20201201 #2
[   17.431385] Hardware name: Supermicro SYS-5019S-ML/X11SSH-F, BIOS
2.2 05/23/2018
[   17.438778] Workqueue: rpciod rpc_async_schedule

metadata:
    git_repo: https://gitlab.com/aroxell/lkft-linux-next
    target_arch: x86
    toolchain: clang-11
    git_describe: next-20201201
    download_url: https://builds.tuxbuild.com/1l8eiWgGMi6W4aDobjAAlOleFVl/

Full test log link,
https://lkft.validation.linaro.org/scheduler/job/2002643#L1005

-- 
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYvhvZtDYVBo4kj9OkKY_vVFSa6EbWz99iCmRPojExRieA%40mail.gmail.com.
