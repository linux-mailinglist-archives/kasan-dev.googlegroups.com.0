Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDMQQO5QMGQEAQ53HAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id D56179F3ED7
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2024 01:38:38 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e3a109984a5sf5923644276.3
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Dec 2024 16:38:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734395917; cv=pass;
        d=google.com; s=arc-20240605;
        b=OglNMU/v6aHDoaD3IDQmWLzOoKezB/kc5XFSOQerC+NHZ4ldfe9H3g9y5AusrD1pEc
         toHrbbzMUN8kpkfb6MMWqOaqEaF9Ot086t6rPNOOQ7oPETyTLDch58lYTfXlvZWD2kXy
         gxX/QJarD0Umgkbw7HVjTzYVpfiaOJd0T8/jgCHpbeuRqf5rsyo0fx2jhZXYshRImvmK
         dRXfOfc4bLWHapn46t0P7i3oSZ023g4NvTYu0WThPmwY+qeCiOYf3Wi//ux+3Hz0B0zG
         pLPDm1qcEm6ktB541Qd+twQGNh3xX+Kh0lA4AW8V3htSsiGlusl+cTixcKTa/H1HNIJD
         7Upg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=571wHPwgtw1taCQiTvMZ8hQz6hg7Z0bJJDRD9dBy0es=;
        fh=JWk5P6UoNvLN+mkWSNz+a+/W0Z98tBKgK3KJkN7cxNc=;
        b=L6QyvHcAeUPEalk/sGSKeG7i2zqwAF2w/N/aMPF3TQwLHvlv7Tz+Md4f7+IWDDhWVp
         OktMDEdbOPL9JUUDJY1LHF1ZRFOC5zZBOQ6BG9X9m2KqJRL8hA8kRWmQo1VHbxPtDzPB
         S2CQDMve2uD8nEorVmYzx7pxHEAIoHJ9BsfFFyEaMYY8wesK00w9rVEhAehR3cirRHZV
         NM18vML5W4tn9rw7dXzr7IyDqCyhm09s2h/2qaUKUp9bOtPdNrvewaCIBrecFZATELTb
         1GjQ21R3R6yl/DBj3Epa9Qe9hKHOVyd/KUM/CnrkvFjwPfFe3AaJTNWDO7Kl8NzNHyf/
         JGIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Fg0gPduz;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734395917; x=1735000717; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=571wHPwgtw1taCQiTvMZ8hQz6hg7Z0bJJDRD9dBy0es=;
        b=a+ZTb5v/beJMzOl0OEfZxeIH30r1bZx19Ye5crYCl1QhVjIBbETJw0p8uyCnd4lcSU
         x52KsrmBLznwY+JgY7E79IpQTm2vfb1TlsZjVoj030JH3gJXWP6OTWJgFN9WM2CMe0cK
         Ecro++Unxe08h8dEfniP3jvCMqu2O85UHP/V7AOjSXwTb6StU+ttI35ySroWhIHaA727
         YlE0qZEp50xNfcRr0rLWrdfepZRQDzftUfocq47hLLfLwo2q4f3cxn5I5GTt2W9z+mjP
         6lkbT7ljAwIa7WxpHDBkGiEfQWxzNFzQJR3KIB5isMquubZgb2IYW0Q9BccQUPNCFOrc
         hpdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734395917; x=1735000717;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=571wHPwgtw1taCQiTvMZ8hQz6hg7Z0bJJDRD9dBy0es=;
        b=e5xR6dglfKxehBiQFCPgr2XyRSACQSzZxoSXczshirS6g0hrn7p+yuFm8dk58QU7N0
         2weUylI+3Ms0euybawJaAIlKSDtT1QHrorH3rijbTF/DV8amfXrPt2MBub4Mkiqo3a6X
         BEwMFF/WCwJm+xcuwxxnYmF7bbQk8WyqckQspSTDNpQ0Zr/AW0SBZ+bTOn2/Xz36Jl/Q
         Td/ej/phg8Ds4gHz/3NBzoc45I/aidg/8Qszg0pZiTxZDv1xTmcYxT2SNzkvTdcQtrI+
         KoKTIO+rcA/Acom4l7QAdlOF4J1de5bkclfI3bpePE4sVcMINZA5HyWIYKPfcbIJxqwE
         PFgA==
X-Forwarded-Encrypted: i=2; AJvYcCXvs+0hMAjbX3nv2hlD2k7c4TWFMDND3B3I7u+FJ3lN5LEivTWzdV8YkaMSnZfocjcSDz6FVg==@lfdr.de
X-Gm-Message-State: AOJu0Yzrhfrl9EC/kafokTQTqx51ZgdfllxlOJI/KlKcJuUD3rGL94iV
	3Ql4hVhco8FskNDPRABz7Jl9Won+d5snyOa2LjLwUjRlMSewzWBO
X-Google-Smtp-Source: AGHT+IHc6I9z8dY+14lY9luqRIyW8WwCXsimwdwdAOyQ9f2+E8hl97lyw20o++78vSWbwY3JCc/KWg==
X-Received: by 2002:a05:6902:2405:b0:e29:1b94:ef67 with SMTP id 3f1490d57ef6-e434a823e2dmr12575529276.19.1734395917236;
        Mon, 16 Dec 2024 16:38:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:48c2:0:b0:e38:51f7:9474 with SMTP id 3f1490d57ef6-e43a6eeccedls5301276.0.-pod-prod-04-us;
 Mon, 16 Dec 2024 16:38:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXsTFEfXNIWhF948i7C26Gwe25920VxFvLWZk5GCtRJ2T2tfqffOJNrSHbuwH13Rv2YRkwFxpztiT4=@googlegroups.com
X-Received: by 2002:a05:6902:1612:b0:e39:8558:d9c5 with SMTP id 3f1490d57ef6-e434a8234e7mr11681234276.18.1734395916422;
        Mon, 16 Dec 2024 16:38:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734395916; cv=none;
        d=google.com; s=arc-20240605;
        b=NRSBV5h33l19ssQHRBVbrSWCQqWnGj9ck1OxGbhRg55IDCyEzAXv8r1AXR7MadnACP
         TcADug48sS2gHYrUI5g9R6KJvMe+K49ltH6mJw/ulIXyqWiznJEVlXX5pB684K9bXwAx
         UjpYwFWszt4TN0ZSf/btCOoOQSfU/vyEgDxwD88q9qbdvgkrjjBUNBiVEeqzIEKtyPVe
         3dDMaXj2Kp3pRqTB5jbi6FySYVc9nhFzeVfTsRMO+UauQWrM5yq/4IFGxzrA1rE1ivci
         IXUf9tg0ToYH5dCsSQZbUw+OkictJGN6q/OyotXX18uUPZpCdo5dPcxm6XgjP9O7ZSQo
         J5QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0owI2T3nwz+n+Cwt3sDdhNFYeGpNrAP/tKDySnweoQc=;
        fh=ofsD7KG7n88o06lSHn57+1SduxDKWUPZ1KUkwFB5M7s=;
        b=ab8jgBSg5qpUiO8uAIfjcXxttvUcPXHjsL5It8i46zuPsXIS/Uh8a37ro4OpsL4m5c
         oaJZP8HZCIkMm9OO3Cwc1tjfl+LJ1lR59+kx1YKa7dwrIhPyIrr/cY1JS4wV3f8my7eF
         6fw75TDSY+GS2KEkBHDwLppvp+6+QoSjQJoKI5yNlLLpSJJHgEwTO5Vkjk1gE8JiGkyW
         T58T35uXRYkXQvIAsrpGdp5fYgzIL4y1rwzaQjZeXMNcpOx9eoB/nmY4hcujrw0RabCb
         nsWMfFXOJwtqC9zuaeqGXGLKhqqxeq55pxuWmX9QzsUHfKsh2GfylWAZNlZlm/HcKhdV
         jJUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Fg0gPduz;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e46f74630f0si252564276.0.2024.12.16.16.38.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Dec 2024 16:38:36 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 2AC0FA41B25;
	Tue, 17 Dec 2024 00:36:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9136FC4CED0;
	Tue, 17 Dec 2024 00:38:35 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Steven Rostedt <rostedt@goodmis.org>,
	Kees Cook <kees@kernel.org>,
	Marco Elver <elver@google.com>
Cc: Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Oleg Nesterov <oleg@redhat.com>,
	linux-kernel@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 1/2] tracing: Add task_prctl_unknown tracepoint
Date: Mon, 16 Dec 2024 16:38:26 -0800
Message-Id: <173439590402.2288303.6690589716880149969.b4-ty@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241108113455.2924361-1-elver@google.com>
References: <20241108113455.2924361-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Fg0gPduz;       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Fri, 08 Nov 2024 12:34:24 +0100, Marco Elver wrote:
> prctl() is a complex syscall which multiplexes its functionality based
> on a large set of PR_* options. Currently we count 64 such options. The
> return value of unknown options is -EINVAL, and doesn't distinguish from
> known options that were passed invalid args that also return -EINVAL.
> 
> To understand if programs are attempting to use prctl() options not yet
> available on the running kernel, provide the task_prctl_unknown
> tracepoint.
> 
> [...]

Applied to for-next/hardening, thanks!

[1/2] tracing: Add task_prctl_unknown tracepoint
      https://git.kernel.org/kees/c/57a6baf3a3ea
[2/2] tracing: Remove pid in task_rename tracing output
      https://git.kernel.org/kees/c/a6115cceb1dd

Take care,

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/173439590402.2288303.6690589716880149969.b4-ty%40kernel.org.
