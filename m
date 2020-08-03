Return-Path: <kasan-dev+bncBAABBY4BUH4QKGQEBUIX7EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A2E023AAEE
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Aug 2020 18:52:52 +0200 (CEST)
Received: by mail-vs1-xe39.google.com with SMTP id n10sf5086148vsj.4
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Aug 2020 09:52:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596473571; cv=pass;
        d=google.com; s=arc-20160816;
        b=JzU4JgB/UQlGHRE+0i69ayijhkVjOEFezoLKc90gSKq8aCVujl3PpjBbX6fIbS3kci
         wQA8y0ZG7Dl+2iIrblFkmMQn/J8iBEEGZMZEtMM7m6wdkgH1DEcZ+vz3HhdumaU0KVee
         FDlGdedCfsLYrzsEknXgeb+U6j/78VQx2oa4qce1R/xsyZ41Y43C3Si5Y14NCQeswXbl
         gYOR8h+bzaBNEPeRGb4Qv7C/e7Zrj0A8HrTx3b9AHtfDs69YhinOMxvPBp1PLqjOucc5
         awZ8Hnxc9CNGQZM2TgT9/qhj0NqQQ8mmd60PrN2En94ZN+ZQz11duxZGrRX6T+BNbURI
         YsNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=J3HdxX7ri3kYV0pt4akMUjuiXZzXiO/0WDKJ4RN/gyY=;
        b=xdSsa7A1YY6oIl99lod94MP3KoqKvdroMy/Uk7SsEEwK2Y2/BdOS8UE+2ckZ7p/ZNC
         tQpZpQYwJqOJzAgj5Q4uJqWRThz2T5/sBZ+mWEb1nuVF6LrWzWsuRpMqePEW83lmENT/
         m56gzJDLr0Ats7GayYzCeVLivAIs/nupjWV2yYXNKGN1IVLu4/joga2ZnWdBIKxKuQFe
         iVlaB3mR0FrLQr8EIydCjRJcLwg3iMByrLT0tHz6C5RZkr3PkMX4IqOwdXss1OqsI1xA
         d2UmYnZUdEjT6PwIWdmH29mzSOzS2UOF+FDMCXPfjnKJBzd06/toEBOVeW6RTLmGwVYJ
         OCtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gfdlfqbK;
       spf=pass (google.com: domain of srs0=a4hr=bn=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=A4HR=BN=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J3HdxX7ri3kYV0pt4akMUjuiXZzXiO/0WDKJ4RN/gyY=;
        b=oVZhUSQIFUbsWPQpDevU2Et8aRZ0V3EvHJF/QbT7/Is+QFqWLRPuf8dEk2hW5FU7ah
         nCu2nydl+31CXVo/JJXSCY5DHwrXq2tnNB5F++dIaLfTAJDh2c6s5OiMoiWw7d+LevjM
         4WlfUtbc1jCGhPs0lhCQaFf9T5PDKQmGc2Z2SLk9bGcrU37NSlLrDU8S+tyALjxIUiKr
         VwAlum0Rj15sV6LpSqkEcP5Oq6Cgtj1PsLfTccEKF1CXL5lRrN5WSaO75K0beknSyq6v
         bTf88g2Gi05s03ZAij8maTq3CLnc2AGUWgRl3gOIZVxSeJ6Tv8YZa1WtB192eGvo2MQ+
         /ibA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J3HdxX7ri3kYV0pt4akMUjuiXZzXiO/0WDKJ4RN/gyY=;
        b=edWG3EFdPyiv6PJDU/urp26eYPU0RPKIMkxWI40FLyDoVMngG2WgZHs+s1v9idbpom
         BYPDzc+Ga9X2KKEI8P2KgCvGvG6nbClED1vfchSs7uwhF+WwcMKBjxd2qPIIPc2rUiQ8
         xMr5+KeWOgKzQMBI7jdHIblcJZ9f1a40ODOIbUmhvwEr2gkWvi5/ve8EdrVdcrVg1ADt
         neL7vvPkUgHRtM5/yvJTNBNHL+Y59Jsq8YN4t7myK0+CwMVe15qSOM3E8zNueppxj5lJ
         VxDq5xD5b+LOqD9gu68aARRoLba6SVixq8s4lY+lpThzvrePV3LfrwWhJoeU07+A+7Dq
         q0Eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jB623XsM/Y1zkfLSoXdDBjxOGB3IxucY8NwSB2aRvj0KVPYW5
	26p4Q+oLYv5pg71yFTSeboQ=
X-Google-Smtp-Source: ABdhPJyylYPZFC2BbVK2E9NLcg5mgjqWWuiYncbYT/V5eLVuLA4zq8bUKLbhcz4hvofYBU2zzHAjlg==
X-Received: by 2002:a67:f698:: with SMTP id n24mr12605895vso.50.1596473571398;
        Mon, 03 Aug 2020 09:52:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:31a5:: with SMTP id d5ls1944424vsh.4.gmail; Mon, 03
 Aug 2020 09:52:51 -0700 (PDT)
X-Received: by 2002:a05:6102:c2:: with SMTP id u2mr5272166vsp.141.1596473571167;
        Mon, 03 Aug 2020 09:52:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596473571; cv=none;
        d=google.com; s=arc-20160816;
        b=Tvdnhv0qY9RDhF0pAZRvQDQZFRAm0D0FD+aPNm1bAqzD4nby1BgcnpHLgz73eFFYOj
         Zp67Ch20/w7wCuo0Rw8HDt3T2NNtLMD6Ar1Gza2PVu0apwrEssrlG8o18JQeTBp6YBya
         VzvqDobCciEDUljZDEJO8JrAXix5h5I3QgUJfWkkqPoLPtXMPypfyj7TKlyU0DxECT+0
         nVHZq8guyUFJlno+1lKvgjeYB/H17XNXbs9K9vXGDIh/W/1BiaIQ2kU6OCJXrxzz3tOw
         uxBq6BtiwKu4bg+bXlE+LoogPh60fi72DTFRVMZGxXTf8PeUYNB4tcxPRmm78cihuTf2
         niEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=TnLrCMnOCyq4gUQ8yZCpDoCGM8lhn9n8MGfOqXNo3eg=;
        b=KeYaxgo/rhS8clrSKYIl5qhMJ4dSIPnvWCzaFcgbkZ8ewHsohdj9xtmf+xUd/d284r
         tYL//AJCoWvzUUMRF+dz1btQ/g2sL0RA42yPyr3sorwppkapDOps/jVSxn21yceOtEYv
         eh2X2e2Dv7FWAIY+KkdZbAl7T/BlMwAL33WHQvLw+aow+pbv7yI5qx5Wmd2idFwinhk7
         9ILkHifrdnPzmepy2Jr2UP9GOQUcBP9Q2yVXCbFS96Rcs5HOw6kRp0kjy+QIexHbxrq1
         Bx37Wcvbp2cPI6whUsf8vrMlCqyH5HhykJZ+kYTD3Tih4bPrjfw5G+e2n9fsa/hxBDMv
         6RlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gfdlfqbK;
       spf=pass (google.com: domain of srs0=a4hr=bn=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=A4HR=BN=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p19si217104vsn.2.2020.08.03.09.52.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 03 Aug 2020 09:52:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=a4hr=bn=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 02355207DF;
	Mon,  3 Aug 2020 16:52:49 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id DAA0435230CD; Mon,  3 Aug 2020 09:52:49 -0700 (PDT)
Date: Mon, 3 Aug 2020 09:52:49 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 0/5] kcsan: Cleanups, readability, and cosmetic
 improvements
Message-ID: <20200803165249.GA28157@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200731081723.2181297-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200731081723.2181297-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=gfdlfqbK;       spf=pass
 (google.com: domain of srs0=a4hr=bn=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=A4HR=BN=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Jul 31, 2020 at 10:17:18AM +0200, Marco Elver wrote:
> Cleanups, readability, and cosmetic improvements for KCSAN.
> 
> Marco Elver (5):
>   kcsan: Simplify debugfs counter to name mapping
>   kcsan: Simplify constant string handling
>   kcsan: Remove debugfs test command
>   kcsan: Show message if enabled early
>   kcsan: Use pr_fmt for consistency

Queued and pushed, thank you!

						Thanx, Paul

>  kernel/kcsan/core.c     |   8 ++-
>  kernel/kcsan/debugfs.c  | 111 ++++++++--------------------------------
>  kernel/kcsan/report.c   |   4 +-
>  kernel/kcsan/selftest.c |   8 +--
>  4 files changed, 33 insertions(+), 98 deletions(-)
> 
> -- 
> 2.28.0.163.g6104cc2f0b6-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200803165249.GA28157%40paulmck-ThinkPad-P72.
