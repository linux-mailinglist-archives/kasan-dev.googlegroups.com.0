Return-Path: <kasan-dev+bncBDT4VB4UQYHBBSMLS7FAMGQE4LULTOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E3D2DCD2036
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 22:38:18 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-65744e10b91sf1835003eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 13:38:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766180297; cv=pass;
        d=google.com; s=arc-20240605;
        b=DuvoDYOgELhFRTQwp/I93FBOatHHRLAcqwMCraOBDVhYRRLKbE6Y6DkbgZIcrWb7p6
         hbvgrPHytRH7ciFp7Jz71HYkMRlH8IiD15Blkop5+eTiEU/eV77OhEAoAzypx9ja6wOq
         DYQrAyy5gO22fZMjerP0U5wuK24tuyHK6qSmtSQsnma5jHwziBe1AKhNkDObu0VEmeV+
         /d4a2N3FIQNdrX95A3Lq/PvvuYn2A7GOMrVd0yddjVg1rXXJEhykZ9RfQTC5VKcbDakM
         dNYG39CSp1aUQnNRPfPFwqlJ2qiR02I4OrACpJI3AJ98Glkrbi//9QPkOMlVVxLjhvL+
         Wdrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=gtsqEqr9H5shqPhXnKe64pMpT5Ci5jZUvJT3+slBU0Y=;
        fh=l7xybPH/2lkABbUEzOzukPbUne7OPmwLwXQJEh+OwkA=;
        b=CUwaHOIoy0bSEliN13+qIA3HB4d8Q8+pJMxgf2sFCFMi6BSE9wQvAwDSoQZTukYQYq
         vNKkLph6ZfI3qVfKBvwAsycO8yFJsZtqkBrkRuBcTGJcyaW7JnW53+NETpZAEKBzoFhh
         DzaBbalQ7AiW2UOfAOt5WQLLVGxVOEUUMCuT09YGLeQeisKZGWc1mdr0DwUnMzGheBWb
         agABjhcwR18fXhZ/s3Te/YcLLdAVuNdMfCNjONs9dFuedtADG5ujVzorB/Cxooqezpep
         zDhXfUv9X2CT+pZKQ/pqzWfJrfk1uhTMPr+zBXTRG29aYPhs9a57nq6rlMnwH0yMlAM1
         dh0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="lWDA/PeG";
       spf=pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766180297; x=1766785097; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gtsqEqr9H5shqPhXnKe64pMpT5Ci5jZUvJT3+slBU0Y=;
        b=u/Mljj4kAWkDqHtbkapSkmUUbv5CjoSlIEECWtRzB1E3i0+TEiqU2QbmrYUolqSvHu
         NbLIm86G8ISdySrIiKT6nQ5vbi5utfuWUpmZr/ZK6cxE2aKjP4oTBlTCIoVq5g6MWfS7
         05PYHrtqEwX5m5gUdkZwyAziSeC2K10CymHKGBktIQD8BPZ+4OQnlRtxVl6yu01Pstgx
         fLknQemf8r9eOeEda59U59jneQszM+4473txKWot2Wmr89glwTdNevJh+yC41UuymSVq
         aChlpYm3fSfyNyrxILC0FSpd3mG7QmpcSUUNdv1EaEAQ2XCOxRjgANkIf6+LgpnZJNzS
         5l6Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1766180297; x=1766785097; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gtsqEqr9H5shqPhXnKe64pMpT5Ci5jZUvJT3+slBU0Y=;
        b=FR4tAbcV7iUZ1D52CyfdQ+ofDOBOlNIsh8NuCQEPKv5QIz5IeQQtJl8bw2NFNwuBKw
         AjT06nyA5E9cxt+amOKNupHXv/8lbEE6DB6JYGK2gnGfihd4XQFJ2oRc4UHXu9n5L0bI
         0pBMMGR7Vs8ZFiHFc2TwF9BSBRIBv0lg755gSwtJs1BIxZQait/pFJs95ld9zWbvVegK
         55mQvxUD/fP0XTIDDZMtsANAn2GEr84y0U9D62jNkUqxNVuir5Cg/N4l66Vo7wzSFbjg
         5IVY4BbeaniZjw/xHyxGBzQAQJYJvmhdH7wN/VpzqqOgNYKitbfM6aK1pb9pzhPkZ5VI
         Kmhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766180297; x=1766785097;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gtsqEqr9H5shqPhXnKe64pMpT5Ci5jZUvJT3+slBU0Y=;
        b=ggAl7kF5BJQOdMFQDPsvAluqjTxd3wwc6kEKTdpzLjTZHEA7Vg0itjMsPOqkjSyDOo
         MxU1609BLI2biSzlAn3uCoJhFq21JCk2LGGRqqw6mCyuOFmptDqUmLyAiOi/hOcp2ijR
         9/IGiS138PA9hDunAT8s2/29FUcYFyzRI1xB54fB+dW+sJdw5xY9RUB9zZ+ddnMZKzj0
         PqN1TrBrksI2IsE4nPHO8axZUaaYHDzr00Y330aQrSolgeUOkaqz1R6E6bm+ZzNoEYMH
         +J1PG/hnJSHZIHb4ufqsH220lLD5fs9A/OL5h1GfIODH0v8nSpCtz/A/kie5i/XDxKqL
         5mUw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVviaCQrMwjMN6ovj/a0Rw8GWzHI+iAsO0P9zgYlywzGOGOmb1E3Di5BQrYfpKgf+lCmURLrw==@lfdr.de
X-Gm-Message-State: AOJu0Yxry+ykimpxBvCALiuxive+rmjicpYi1CVNWpK3FNoMfGNt1cL+
	/bj2npP1P1RlGTDM+64CKa9H7SvcoTtqxzegyE5JarM+coCtJcQ0SLvR
X-Google-Smtp-Source: AGHT+IFYXe28v+gCX2cu4xn0qxSPvMojYa64/1xSrPaigoGj3Xko/XnH4bII+gSYz15GVm7u6qrf/g==
X-Received: by 2002:a05:6820:f029:b0:65b:3520:daa0 with SMTP id 006d021491bc7-65d0e920fa7mr1864573eaf.11.1766180297595;
        Fri, 19 Dec 2025 13:38:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYMTbLBphJCU2oBhfNIZd9Q2+jRMlk1JVBAPXI0/1p3Nw=="
Received: by 2002:a05:6820:e00a:b0:65b:79c6:1e36 with SMTP id
 006d021491bc7-65b8659695als1686284eaf.2.-pod-prod-02-us; Fri, 19 Dec 2025
 13:38:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUEWUjva4E2pval1QZlbv02vnoUSlgFwtzYsOlqxdv+3pQ8IUoTDm5KWwPJuipr5Auvsa5JFEAQJAE=@googlegroups.com
X-Received: by 2002:a05:6820:160a:b0:65d:30d:eaf3 with SMTP id 006d021491bc7-65d0ea624a0mr1701558eaf.42.1766180296481;
        Fri, 19 Dec 2025 13:38:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766180296; cv=none;
        d=google.com; s=arc-20240605;
        b=gyFvdGs/DL6a5zK+HWJpFcTkyag/CV+34bJer28q2qv2ODSc0/ppZLJoQhEtq2Bz6c
         fCLhkpd6UKPl/ubXodqFjBl4YHrnTEeRO3TJ8wcAyP6iuw3lXT264dYbFegpEwQEeIHG
         mE/EcvPggIqfvfbtOQDc5YyuX6pdZpSq4K4uLqOsqxZD5Kq/4lxuyR16du3mL9uO6DCz
         F57QFflmrJtTg8E76l14tRjxUKt/izLJo6AKKBG6OHqXnNZ+fualuprS45tdlbr81uyo
         1QOsWf9Om/LIcXDJYG5nn7K/wcnT1W6Dv2m+Ul8bcdne7HRfG9uEcQHTHtCn3JJyMRHG
         D8lA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=SBHXkRgMesGUJGSlI+YkckhHJhyJOUbeeY6s/H5FeUc=;
        fh=1UDIRXjMp27hdQdtFGRf1cUa+2epzCwbzoxzEWWG0ko=;
        b=HRw1NRu4UWXfGF8B8vyj6Z02tXELU/bTk03kEQoQQ92o5AcSpzbspTlo32zfk7i3lc
         SrK6aPadVZ6vpTYxByH9iuco7JYookG9QksyiixPmXzlX8KFF0I5gFM2FDDLOfYtk3rQ
         1uon2HsYUgPwk0kTQX6leX2kManqRmJaW9HWTpWlhmbWZA62ZGzi1ksfHkGwV38vOk4b
         tXU51kylNsQwqE0XJtctYysyd9r7qvCSFRpL4EdeyGdT1Opo9TsgZGsfRW51Mu4nQX41
         1MWffMx/WiZn3Kg1bQ2Yg3jQxve7emBVvoTpfMzKm7CEzN6ILRqrHJNh3FQVUm/WdpX8
         XR9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="lWDA/PeG";
       spf=pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3fdaab62035si168750fac.6.2025.12.19.13.38.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:38:16 -0800 (PST)
Received-SPF: pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id d2e1a72fcca58-7b7828bf7bcso2421544b3a.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 13:38:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVtl7qp8P804/MIvkT/l+Q2QQgFDf8vBzRPSYF7iiXteYD0rR5nHqhyXhGgHgxb8x90kxLBRPk1WMc=@googlegroups.com
X-Gm-Gg: AY/fxX7o3B/v6Jp8r4Ut+33xyW7q7TiGv094YhJaamx7WtUrBFf+oXtBxyvJC7K5DVG
	AQwb3iVRwkiuL4J/7uMq7b+G3Uht4cILcyrbfvDoz++3Tg7pCIxdyWT0AiOJ7NQmBlefDEDoEAi
	Qavd0I/4XqXFunfjzKtJBkA+ZcC0zKqQduag+VqCBgW/+8uXtN69iFpG1zV/KNoBUVvK/EZ6dxR
	tXtnNVHZNQkX5+YaZ+8gFnO1UR0w+rsPfLu8hcOkCUooOZxetPGINrzqEA8KhkjcqrK0ij1T1zO
	D9LIJyCd7f9OsrQrbnMIvos7Px0flv+f+OIxNQN1GKqtz0mhfgsP+R4mHuQPrCoKAWdE/BKCkCQ
	ZUDSrFvUDUHFPSlFVp9d9IUK4pySyV4xlowPb4b9gDG87cBsNvHjeRGO5IzbArelwdpkQMpk2cs
	wFYYdeQeyhlEDIfq7WY6fzRvSGdjtljxyQLccstDnlflxd4tNeQAbmt9zDcVko1UjvG2+X3D2sl
	l4wXAH9IYGz4vAc4fH8JetVOf/tM1dJezEzjdAJDuYZcfvJGRWinU1sjyAJ5+8DA7u+ZSpWm2U4
	RKE=
X-Received: by 2002:a05:7022:e0c:b0:11a:f5e0:dc8 with SMTP id a92af1059eb24-121722f462emr3455845c88.28.1766180295388;
        Fri, 19 Dec 2025 13:38:15 -0800 (PST)
Received: from ?IPV6:2a00:79e0:2e7c:8:5874:79f3:80da:a7a3? ([2a00:79e0:2e7c:8:5874:79f3:80da:a7a3])
        by smtp.gmail.com with ESMTPSA id a92af1059eb24-121724cfd95sm12051531c88.1.2025.12.19.13.38.13
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:38:14 -0800 (PST)
Message-ID: <34cda24f-acdc-4049-9869-b666b08897d9@gmail.com>
Date: Fri, 19 Dec 2025 14:38:12 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 23/36] compiler-context-analysis: Remove Sparse support
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
 Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>,
 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
 Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
 Eric Dumazet <edumazet@google.com>, Frederic Weisbecker
 <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>,
 Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>,
 Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Kentaro Takeda <takedakn@nttdata.co.jp>,
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland
 <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-24-elver@google.com>
Content-Language: en-US
From: Bart Van Assche <bart.vanassche@gmail.com>
In-Reply-To: <20251219154418.3592607-24-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bart.vanassche@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="lWDA/PeG";       spf=pass
 (google.com: domain of bart.vanassche@gmail.com designates
 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On 12/19/25 8:40 AM, Marco Elver wrote:
> Remove Sparse support as discussed at [1].

Kernel patch descriptions should be self-contained. In other words, the
conclusion from [1] should be summarized in the patch description
instead of only referring to that discussion with a hyperlink.

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/34cda24f-acdc-4049-9869-b666b08897d9%40gmail.com.
