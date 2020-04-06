Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBGNEV32AKGQESH3A6TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 00CAE19FF1F
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Apr 2020 22:33:31 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id h4sf1050816ior.11
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Apr 2020 13:33:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586205210; cv=pass;
        d=google.com; s=arc-20160816;
        b=NLWrfwcVuXVYSn5kPeTv3p2jB5VX3WGpvZyIl27NB6lqnHR3abeUawAjYN4AwXbIvx
         cv85LSRv1hCvyxI7pddiXkmsOORYyz8T8iHLH5S7oAD2KK5C8Tj2uYa3g4szTgn6rHj5
         jcFTqffm4fgOvUDvwPwOOxcrJVFxgj3aZ/oqBpz0nK6i6R/jIKKXqZucB3wwOxcnw8Vk
         3bzHs6FwEERyPJMK7Ayjcc9FvPJIIYuWZp7x1bWV1R8Fyez8QK7hTbIe7HiLD2IKlxYI
         SrAq1bJTZ/PxMuJEQaPBcA/0DTbBG4E+5SVL9qfelqS9k644FOcS4Cpf+1Zefc+4FIpG
         eDxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=B0K8ASMRb9D5WUevCrpGd0ql/00xr4VjKW0kCRHXKyM=;
        b=MyC3z7/q/VmYD/jz8eVbwlURXy+ZZUFwXXc1KYI8V7yY2VgghVY4mJyQEH7ox7EfMy
         gmQKKegWQUgBGU9P0lR+OIi4KDzy2xaPBclSwuXfGdxgagsSqWI80IPTIhGtGsrfGaff
         Ly++jCktWwdCGV7uY9y5tt41P9GcTdT0MEnvITM10bm++3AzAyA9b6/a5Bgd7+Cyv1Rm
         Yq99BThSKIX5BNfWIu6GCyIGuV//oywASf5gSV3kJfnwHvm2rl7AbGJu+D4qtVW62JC1
         A/tD0KfFxIgJ4ViwBUqY4Qc9eiwr+bGKHv6vT6KioyoFRFvs2YDwosOP4ddaXndivb/k
         Ynjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=E6gDB1rO;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc:message-id
         :references:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B0K8ASMRb9D5WUevCrpGd0ql/00xr4VjKW0kCRHXKyM=;
        b=d9JXRRc5mH0y8h70+JW6QsmQVGLNu4CnlwC96IRqtocFvAj3ZbJu9GmQ3EFp65ENwp
         EMqqC2OtECbfnCm97Z0p423r5xHIekm+UJjlgE+DgBUMDrf3/uwWXBRT84PyvzmeLtl+
         PBJDI/0O3a5oOVj9DkI4t+vG2u17Qa0q9bSNbJj91MIuSljxg0k8U6Qah10c4vFFJ3s9
         t7TS4PcMujEDav13tcmHx2FfDteRgUmbgvSCK+V1FCKDaHVQ2N9Ml3pV9YSa5HCIpLcW
         EOnU2My3MocLSPHXjMT/csIwN0EOk08QED2NT3L8TeEhqoPNJGLT9K7AuC70dhTfzf5o
         rp0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:message-id:references:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B0K8ASMRb9D5WUevCrpGd0ql/00xr4VjKW0kCRHXKyM=;
        b=or1MW+BkVpNJdkB01M5FxCHBgIX3h58eTcqEv+QGztLFJtjnQLOcEyJQED/vuztWSE
         i2nm1hhZ1GBev3Wj9MiDI/3RMN4YtJsVid6Y1QYS5JhUMh0dv6XTA8yDYJ7dofGXXWeo
         3NtU4t002Yvbm6zA9oPdDLEEipghyN79h/TE/8j6Y/kQncqbKcgnPlmgKQXzCoFI70nX
         BepHQKOTfKsOPkRMRfmU2cDcVJRE0UbV9cSBwVV2qMd9chocQqsjJM7w4cuM0suSavjo
         ko6+5GdqZ4IgYdIGqei4/4BBQ/CVzBxl59rAcK3J2P5ZUQbRWuY3+IBQFePKvtMcnBdE
         9m/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuazxjmjMBl8fkh1/IcD6oEM1HXziqxqSg8zmG2DdZ4BA0Ve1o3C
	SoM4ZaMpbgePgndlyux1jyY=
X-Google-Smtp-Source: APiQypL9r+xOPJoQeTdIRlsc04pfx4cDRbEhuj1WX5L70AeJD0CIw1HzS6gPKUAOvm1jeRFWK7uOFg==
X-Received: by 2002:a92:cb09:: with SMTP id s9mr1218566ilo.182.1586205210011;
        Mon, 06 Apr 2020 13:33:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3ccf:: with SMTP id j76ls590289ilf.8.gmail; Mon, 06 Apr
 2020 13:33:29 -0700 (PDT)
X-Received: by 2002:a92:9149:: with SMTP id t70mr1357452ild.114.1586205209602;
        Mon, 06 Apr 2020 13:33:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586205209; cv=none;
        d=google.com; s=arc-20160816;
        b=RQg/z0XXu7lP3pVG61G3D91PVEIoieivyyizTUFJGI1WXaa7eTZvEuqHr03pU6MeXU
         eWXJaQec8+TI55oA7qB+0k8RAJqZshsBWu5k72xwOLQLWmwtKb/v1IOnFWk9HzbKnmve
         aahNDOc/oWwMy7jetRFG7MJE8qjWC7JH6xJXjc9p23EBdPkpG/zy6wZTpz6RKzsr1sOP
         oQUeKce5UVbCmc6Y/8tGqnGiA71Tn9Dxd1tUkS1P5QGeQ3EASVfDLnegFz1cxk9iCcln
         YNm2Tn+ipPbg4ebzMS0pd02P6eRxA07zsH2j4vuEF6NtZonYCEHUchmMYt4lKLSXi4Ja
         NGrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=VZndNblKg2Lp/IRXBvxJ8CPTAZH6z/6SP71Yf2KIiBw=;
        b=xfVMmu0N1VIgwMEYvC5C/vR96Cjyg0vj1Xtby98zNSRWrC1FfCjxnNlxGkOyFJIyvf
         gptjlavUg9AJDOHho7blnplfEYM6CbeYXaL/0qxOkeCoLLim80wD9LY+vqpKZfGTvERE
         Vk/uh/Jc9T0va9IrI1HkhORpYQTVUtJ8KKVSdGCUbBx+nO1HgJSZmM6qLqKI6oK9p7TX
         bDPy2ySEVumbHvCI4nnKNnjDqogRcqmurRQPNgFeFSOHgY/Dy3CXU6rVVNFFBBKmfdl/
         sJk9B0ECOdYHFhhIcDRTOab4sVgahv0KCrT+lpAhrJmAedbqE386KiYDnj5HvheTkiiU
         ZUhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=E6gDB1rO;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id u6si77193ili.3.2020.04.06.13.33.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Apr 2020 13:33:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id v7so17790854qkc.0
        for <kasan-dev@googlegroups.com>; Mon, 06 Apr 2020 13:33:29 -0700 (PDT)
X-Received: by 2002:a37:98c7:: with SMTP id a190mr5636331qke.91.1586205208887;
        Mon, 06 Apr 2020 13:33:28 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id e10sm2728801qtj.76.2020.04.06.13.33.27
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Apr 2020 13:33:28 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: [PATCH v3] kcsan: Add option for verbose reporting
From: Qian Cai <cai@lca.pw>
In-Reply-To: <20200406195146.GI19865@paulmck-ThinkPad-P72>
Date: Mon, 6 Apr 2020 16:33:27 -0400
Cc: Andrey Konovalov <andreyknvl@google.com>,
 Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 Marco Elver <elver@google.com>
Message-Id: <3B06DA7F-DCAF-4566-B72A-F088A8F0B8A9@lca.pw>
References: <20200406133543.GB19865@paulmck-ThinkPad-P72>
 <67156109-7D79-45B7-8C09-E98D25069928@lca.pw>
 <20200406195146.GI19865@paulmck-ThinkPad-P72>
To: paulmck@kernel.org
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=E6gDB1rO;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 6, 2020, at 3:51 PM, Paul E. McKenney <paulmck@kernel.org> wrote:
> 
> On Mon, Apr 06, 2020 at 09:45:44AM -0400, Qian Cai wrote:
>> 
>> 
>>> On Apr 6, 2020, at 9:35 AM, Paul E. McKenney <paulmck@kernel.org> wrote:
>>> 
>>> It goes back in in seven days, after -rc1 is released.  The fact that
>>> it was there last week was a mistake on my part, and I did eventually
>>> get my hand slapped for it.  ;-)
>>> 
>>> In the meantime, if it would help, I could group the KCSAN commits
>>> on top of those in -tip to allow you to get them with one "git pull"
>>> command.
>> 
>> Testing Linux-next for a week without that commit with KCSAN is a torture, so please do that if that is not much work. Otherwise, I could manually cherry-pick the commit myself after fixing all the offsets.
> 
> Just to confirm, you are interested in this -rcu commit, correct?
> 
> 2402d0eae589 ("kcsan: Add option for verbose reporting")
> 
> This one and the following are directly on top of the KCSAN stack
> that is in -tip and thus -next:
> 
> 48b1fc1 kcsan: Add option to allow watcher interruptions
> 2402d0e kcsan: Add option for verbose reporting
> 44656d3 kcsan: Add current->state to implicitly atomic accesses
> e7b3410 kcsan: Fix a typo in a comment
> e7325b7 kcsan: Update Documentation/dev-tools/kcsan.rst
> 1443b8c kcsan: Update API documentation in kcsan-checks.h
> 
> These are on top of this -tip commit:
> 
> f5d2313bd3c5 ("kcsan, trace: Make KCSAN compatible with tracing")
> 
> You can pull them in via the kcsan-dev.2020.03.25a branch if you wish.

Great! That should be enough food for me to survive for this week.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3B06DA7F-DCAF-4566-B72A-F088A8F0B8A9%40lca.pw.
