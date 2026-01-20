Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLULX3FQMGQE2GWTYMA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id KChlMaOgb2kLCAAAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRBLULX3FQMGQE2GWTYMA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:34:59 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 24E4B462C2
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:34:59 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-7d0fec5ded2sf2580137a34.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:34:59 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768923297; cv=pass;
        d=google.com; s=arc-20240605;
        b=JddNktJZ6y78SFCcZ4pRHb1BIq1WCMPQz5z20Ro1ChjcpxVnOnSFCXaz+UhVczmHOh
         5U7O7gnDKmNojZVS3Tgobn+Iquxr+PBicUimDvWRgD3O9oyPlaOi6XFkWn+h0jiL6aRw
         auuuOk/mdH1NjAaXzj/IN1FfU1Um/NfHLuhFoCpZZyAq/C05mX9Soz86bMHXNpysmtkj
         nrKVqIv09zhXE+ZFzpOl5cGJdpL29bc8hLEoxyVBlp/bGnw16tzLnF73ynE/FTwSOZz9
         a7etkDpz0doER8HRVW6eeCaRnBjp1Lcqc+OyDRrQKQBNTK093A0lu2ABRH5wMaGDR/kY
         pIdA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DYRxw10mkW1UrhEKfLVRrV8FlXPEoZtoeUtCK7qcSuw=;
        fh=WSUOTkjULh7+3YhtB1U52o1Qa7tlwqDQd3vEHg/Fgp8=;
        b=ZtN3b9mktCpxty4g826V13tavlPLkOU4H0YPsB5QgLeooZ5lSSUMR1lGdIdqeK3iob
         pjb233MHoCctyF5uwE9HbL05acjElFZ8it7HhkpYAJ6rzzGFcZQLssQlLOqxdRpCtylO
         G724XS29SNTCJWalZ5dcF7nrO/qNb4VQwC4ZgRdcC4cGrGJ+lrmXl3E8Kx1Z2k4J94rO
         5y0ChBs3HxZgSdtE/dhvsoL+4PCA2vLR4Q1xFBFM1eFyW5Hss4ewPvxlD/vlK/gdhGcC
         vHK/JSOQJPSyKR+D7weOORzNwPRWlGkQabvEV0GJrtbxe3uNEBfGnsLPAXdQcKCuoNo6
         ZGZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="0npg/Ju7";
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768923297; x=1769528097; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DYRxw10mkW1UrhEKfLVRrV8FlXPEoZtoeUtCK7qcSuw=;
        b=KDJ9jRD3HgC5X/aHU40pxpXPTJnnouXrmJpfpH5aie7rJTdJkvvVqggVoRibqOuMtk
         z9+btjlcuki4nz7bwkGeKuMzltL1dUIbPXqMSJ0ZtwtOavRFcMd9SCKukEReqJdzOeEB
         Bi1pBSaSVyz/DFwYYTeQ/UZLUQOHPqkieO/z7xFEmVbFE58X4JxVF3dRcTtImOLPrmR0
         ikbJ2/HZNMCNgEl0fySSn+RBJl6QWYdsRs56Z6G0jzkUwGwJd7lJW0xA7CYSiZDr06Bz
         gGoJVuOjrOILRfir7S/6WPFdm+GeZgoG9diUEQ3eHbKFVjXNyU+r72/SChkr9ZvgsZd2
         QlWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768923297; x=1769528097;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=DYRxw10mkW1UrhEKfLVRrV8FlXPEoZtoeUtCK7qcSuw=;
        b=cFKO6OpraTVEc8bEbWswxYj7v/e3U37Vc5kLrxF+SFFw+BD/gExUCcUEAjVPM/WsHI
         kpXKVKbXusfXtEF+b/n/EAOhBVO2vMySdqqMJZmHcXZmtUdCo+dxSlQk+qOt9WfYQjGP
         Qk8MUJzj1TEyz4yBg8NG2Wz1rN7KhRUCaVpbF1CnukcqPErU2y0BKAwYxkhNtXKkU6iH
         XyD6IbcVgxzTLfRmTnYBuXphGICu7Er2U7SufC/Uy1mHTkJBPF/QfYDnrG8SN9i/sIQ1
         5w4aqEQMAYd0kdRKMQZ1ar+ApEoyX15za03E29CJwi/zV1dlaRHz/wdWN734TU12ULDH
         JOlg==
X-Forwarded-Encrypted: i=3; AJvYcCWzv09Pgapm39HQXX/p2GOcIGM03Cv5of0XWTjpB8sKR71frTcCaw4sB/FkguuHYoEcRMdROA==@lfdr.de
X-Gm-Message-State: AOJu0Yw9G2Vbh7MpbEJ1L0ZsaQxsQZPAZ5Yf2H7hw5iX0CmFtC6L2PDJ
	hTEbI3jYRCm60XFU/RrAn+ZEOOqogNG9rSwkjyQKijiUU5j7dMcTP/gg
X-Received: by 2002:a17:90b:4d8d:b0:34a:e9b:26b1 with SMTP id 98e67ed59e1d1-35272fb86b4mr13553951a91.26.1768916398564;
        Tue, 20 Jan 2026 05:39:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EtG8l/45V1ueKlgt41Yx8w2E//sBuIrN6fYJJ2pj0NWw=="
Received: by 2002:a17:90a:c290:b0:352:de4e:c637 with SMTP id
 98e67ed59e1d1-352de4ec796ls202190a91.2.-pod-prod-01-us; Tue, 20 Jan 2026
 05:39:55 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXXNxUv/KyghTAZDCdkDyFdeoY6hb3Jmee2yu34Xr7WzFXPIaHq/CKhaW9hAGSXshzq4LHtuMqwOBA=@googlegroups.com
X-Received: by 2002:a17:90b:3b47:b0:334:cb89:bde6 with SMTP id 98e67ed59e1d1-35272ee0eecmr10890764a91.4.1768916395670;
        Tue, 20 Jan 2026 05:39:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768916395; cv=pass;
        d=google.com; s=arc-20240605;
        b=fvMGqU2X5HXZSrVZrsj6M4N5fQJTmB6arbSYWAtqMBsC42b24dA+JfUrj/G2vkgK+c
         cDS0pnbLZk5X4yV6U2oxN8xYHMHseK94Pvqshh5VVDRxYjGXfYx2PdacTAGR2mZppJ2n
         0bTQgAzIqk3T+nnOQaAAbPQroH9fpkc5mW9WsH09ypj4Jg1mG7HHMeaS/SCtFPSJGi7N
         TxR8UIJ/AFiVPGvkWpUiOeXLHrtK8VBkSlH2kasN+Zuiu4+hCrYMsGNqCaf65aTKmqDf
         irK8vo68U0+Dg5aQygM22p1ZnJi5aBXpWjX+BdtknRNBQX+GPCIzxqC76Do+zRoXJXLA
         batQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0q6rVfmOcQQ7ikYVJ6BpQMxddONQmNjn6LAGePsigA8=;
        fh=K3QydB2psa1zfQ2j85EX3cl6NmEa5TVkGsi4Z5Fb0Oc=;
        b=k19AHRPNjD26wihttPbUnxXrUKoKoq5/E6wsWq6uCMNc2oV2oryL6Fsga9OGyXhRpT
         WLVq2rX+K3YIgD85tgp2iwgL97lZCdOpGX+2m8tw1V/WDp0J9vq2C1DWFMkY/UzVkyHR
         A9M1OrSiqGGEmP/IX0euERj920N8AxhgARPSmKcAL53VwWrS2DHY4oNZ+oPa8959Uzd3
         ldwx552CdKGvRi75xXtr5osIY7zU2IJ65+1bKI9J1GE0OebG1V26SimHPnRq+Z0zEDsH
         LNlSyNlL0i/t8Qf+efFl99ciMS/RH/s3ynBG8c9Hffyjs93Q/OZc5v5qEPnRYZmqYs55
         MRfA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="0npg/Ju7";
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-352733abd18si144534a91.1.2026.01.20.05.39.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 05:39:55 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id d75a77b69052e-50143fe869fso60824981cf.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 05:39:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768916394; cv=none;
        d=google.com; s=arc-20240605;
        b=b61F6eoVM+AM6oCixP6ItLfYIrtRBsV8Ges8kwnKYLcAAHR4IxnUGEBU2XEGTUuJtD
         D/sk3VavH0XVg99XUy4YxY+YTcQ1kliB3LP6D5Mwp/woPg8NrEzTQ9WyNKXeMO1EFJ+g
         wcIsjTZBN2Ice02VS312Cm1GGWnorJv1eALstWKcBuC2UdmRmRS7aSFFbhjSScvi0qSP
         nE3gdnv8ZR15Znn+XiTwbfHbGqntTowkcQcouXRGBh0ttz+P2af8l60ohGU0TNi/zoCr
         +iCxnl4lQ29c+zl30LT1bupI2zTgXdeSI5QY05KLnU5pVnHxiXf/PgSUDSQpPxI19L+w
         ur4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0q6rVfmOcQQ7ikYVJ6BpQMxddONQmNjn6LAGePsigA8=;
        fh=K3QydB2psa1zfQ2j85EX3cl6NmEa5TVkGsi4Z5Fb0Oc=;
        b=TT+Y5jXv4Zrbq6IK6BKKfKRt93RSJ5x8uIuRp/IBrtUyuBfZf1WrRzcmeureurPJT7
         GJWWh15DRB6W3v2damsfp4UfeRYqn5GWfM5pLF92zwCoHEAd9ykwUvLl4JyCSlIN6V33
         ZSuMUeTTiVo1dCZLodoxwgQAmFWEit9sdi5iPTl47du9k/iUzXfsZV9/xglfWxNaFni0
         2Qp9BmGZh7AJ5aYnPtJ+TqkdSa9hnwyavN7luh8GEzbx17+1i1Y+jBt9KDG+uKnJqpiN
         o+HiuBEuUmjFa0yfKb7iRppYRwdBF7GxLSrXK4RtgVMX7V9RACLyCoyQn7DQr5Fe1RLq
         CZ0g==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXCIrS1UkMjS7MQQ9w8A44ZVGYn+LKS8vU9egIbv/AtlCZdhHLETsZCH446MT50XaTbzJjX2NxXYOw=@googlegroups.com
X-Gm-Gg: AY/fxX6243rAB4KQqGdsfcg5itVfirNx/5eya/hIHY+GqbmZdqtjSyP2ncQ+GlaOc7h
	jILM34gtDfibiBgy1QZUp3TG/QbRY0K4xE21j82ClKHfJP2VC0Rp5/at838G008xsgwM19ma+zT
	OUr8ITROu4JtNL/BfRhN5ITlD5GBs2UYvav+IQBG0xVJKWaCjKnPp0zFDzZ9zysD0sDDx2h86yL
	CBanJYfrTQda2jwenDfbqeeCv3bINRKJUDvaTMy8rlqSf18KPV00N7X8A1GXQpzMBsLP5QdPoCM
	nlixSJrXQvLK0QbXvCVxs89t
X-Received: by 2002:a05:622a:1884:b0:4f1:df6f:6399 with SMTP id
 d75a77b69052e-502a15e468cmr183024831cf.14.1768916394245; Tue, 20 Jan 2026
 05:39:54 -0800 (PST)
MIME-Version: 1.0
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com> <20260112192827.25989-3-ethan.w.s.graham@gmail.com>
In-Reply-To: <20260112192827.25989-3-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Jan 2026 14:39:17 +0100
X-Gm-Features: AZwV_Qhyxy4QYBC9vsg-1pl1r-iBwYh-56DZQ4fI_mrGZ4r5y44flCCfgaeUkgg
Message-ID: <CAG_fn=VWpu6eDgumX7KV1LuRu+qYJjQzKqqYyapwyzPFWrAYXw@mail.gmail.com>
Subject: Re: [PATCH v4 2/6] kfuzztest: implement core module and input processing
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, andy@kernel.org, 
	andy.shevchenko@gmail.com, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, ebiggers@kernel.org, elver@google.com, 
	gregkh@linuxfoundation.org, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, mcgrof@kernel.org, rmoar@google.com, 
	shuah@kernel.org, sj@kernel.org, skhan@linuxfoundation.org, 
	tarasmadan@google.com, wentaoz5@illinois.edu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="0npg/Ju7";       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRBLULX3FQMGQE2GWTYMA];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[gmail.com];
	MIME_TRACE(0.00)[0:+];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2607:f8b0:4864:20::337:from];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[33];
	FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,kernel.org,linux.dev,davemloft.net,google.com,redhat.com,linuxfoundation.org,gondor.apana.org.au,cloudflare.com,suse.cz,sipsolutions.net,googlegroups.com,vger.kernel.org,kvack.org,wunner.de,illinois.edu];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[glider@google.com];
	DWL_DNSWL_BLOCKED(0.00)[googlegroups.com:dkim];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2607:f8b0:4864:20::829:received];
	DNSWL_BLOCKED(0.00)[2607:f8b0:4864:20::337:from,2607:f8b0:4864:20::829:received];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid,mail-ot1-x337.google.com:rdns,mail-ot1-x337.google.com:helo]
X-Rspamd-Queue-Id: 24E4B462C2
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Mon, Jan 12, 2026 at 8:28=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:

> + * Copyright 2025 Google LLC
> + */
> +#include <linux/kfuzztest.h>

General comment: please include what you use.
Make sure there are headers for e.g. add_taint(), pr_warn(), kzalloc().


> +        * Taint the kernel on the first fuzzing invocation. The debugfs
> +        * interface provides a high-risk entry point for userspace to
> +        * call kernel functions with untrusted input.
> +        */
> +       if (!test_taint(TAINT_TEST))
> +               add_taint(TAINT_TEST, LOCKDEP_STILL_OK);
> +
> +       if (len > KFUZZTEST_MAX_INPUT_SIZE) {
> +               pr_warn("kfuzztest: user input of size %zu is too large",=
 len);

Let's change it to pr_warn_ratelimited() to avoid log spamming.
Or maybe -EINVAL is enough for the userspace even without a log message?

> +               return -EINVAL;
> +       }
> +
> +       buffer =3D kzalloc(len, GFP_KERNEL);
> +       if (!buffer)
> +               return -ENOMEM;
> +
> +       ret =3D simple_write_to_buffer(buffer, len, off, buf, len);
> +       if (ret !=3D len) {
> +               kfree(buffer);
> +               return -EFAULT;

I suggest returning `ret` here if it is < 0, and -EFAULT otherwise.


> +#include <linux/atomic.h>
> +#include <linux/debugfs.h>
> +#include <linux/err.h>
> +#include <linux/fs.h>
> +#include <linux/kasan.h>
> +#include <linux/kfuzztest.h>
> +#include <linux/module.h>
> +#include <linux/printk.h>

Missing <linux/slab.h> for the allocation functions.

> +       /* Create the main "kfuzztest" directory in /sys/kernel/debug. */
> +       state.kfuzztest_dir =3D debugfs_create_dir("kfuzztest", NULL);
> +       if (!state.kfuzztest_dir) {
> +               pr_warn("kfuzztest: could not create 'kfuzztest' debugfs =
directory");
> +               return -ENOMEM;

Note: leaking state.target_fops here.


> +       for (targ =3D __kfuzztest_simple_targets_start; targ < __kfuzztes=
t_simple_targets_end; targ++, i++) {
> +               state.target_fops[i].target_simple =3D (struct file_opera=
tions){
> +                       .owner =3D THIS_MODULE,
> +                       .write =3D targ->write_input_cb,
> +               };
> +               err =3D initialize_target_dir(&state, targ, &state.target=
_fops[i]);
> +               /*
> +                * Bail out if a single target fails to initialize. This =
avoids
> +                * partial setup, and a failure here likely indicates an =
issue
> +                * with debugfs.
> +                */

An initialization failure could result from something as simple as a
name collision.
Do we want to bail out in such cases?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVWpu6eDgumX7KV1LuRu%2BqYJjQzKqqYyapwyzPFWrAYXw%40mail.gmail.com.
