Return-Path: <kasan-dev+bncBDR5N7WPRQGRBEHLVKPAMGQE2ZDKTYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 46A546758DD
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 16:38:58 +0100 (CET)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-5005ef73cf3sf15030287b3.2
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 07:38:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674229137; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ce5IoFylyRpmo3ynph6RA/48TjK3vX1Ml8fbH2ZDwt2IQdEVCa2dV+DDU+qQbEb0kE
         +hAs2WqOcBFPKGsb1LHoIM6VC/es5dDCFwo/6tokLAC5wK7tDRgRKWis7n8NF/Ab3pcv
         zrDhzxs0KDM7+CvPg2olRKGsndgweXV0vMzFo7RQD1yw21UCZyo3SN/1Y7NZoB1DHo55
         GOyMkJNHyT/SS6JsbU9T0Hji6BrQGm55ZfD2vwYToenl4EE4VhSyWvUfNsjHCi/zJb4P
         cDsq5SCUbCShliKLzwRysRMsmb98scEvCs84QEthcEru3y8WlEnFLWszSSGQkIgx3uST
         WhDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=4/d4WG0efwf+hy4v00NrWCBxITj4NOSQv3DZCNj36ts=;
        b=x3G0c2l0xNzh/QiMBEArsPT97REe8805xHdqO+xy2ijJnXXyRY851320cX8+3JXeme
         L8ZnJ+rtTT9GpnOazeecYcR74zQ5U+QcDiYY0jaMPiOoDDFoKJYmd1j2CacDRgDIGIzB
         HurUt2YCPBmCEmcv9/RzJKSYafUSLzHF+dtwQUNrjYmBqKQ2myOUD3yNctvUCVs5zY7W
         5d+nrSymBrOkczFRmQ/abXZr93J5i9tYhFoo8zgejggd5zxZSLyY6NrvheZHVETcNtVR
         GAEuYGGo3VyGfJMAUrfvAd7g50xOpMqlTpb+W6PQOPVcTHyCLiZFO7kzITvEgJhN97MP
         hB0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b="gzg/QqiL";
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=axboe@kernel.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4/d4WG0efwf+hy4v00NrWCBxITj4NOSQv3DZCNj36ts=;
        b=Hc0zaefg/cA7eojYiIAOvoL+VZGX1nAJ3PMCd3RAI2Z3lp3dYRxThyhcp3aGguwJDI
         r3Bk/6SWA7JkIDgAeA8R0T7GIN4RuAZnI8Shj5ebgTWaa2PDzHYWedbBLpbwBc2+3Fus
         4ZJ4DwkU7D864NVTCu7DeqP6KdScQEvvlAl6LZ7MGd0ipg8mb3M0oEMTTuhZn6wVVcKS
         UkqIz+R7SWyKMONKDlw1BO6lrILPfRccr+nTcGtnXk+Ds/tJjzuo7LznPKyr3K3aK9P2
         7VUGBiDcWZPPh7HiJGl5pTeSpjTecw/hbomGTXBaeg4QOBp8Aq4lPXT7sf/t4mMRfA39
         T4Mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4/d4WG0efwf+hy4v00NrWCBxITj4NOSQv3DZCNj36ts=;
        b=Q3bhxKz2t8e1A3zP8x990F3MNmlQoN314Fe124fjKbETbpBkcrlC9DhN7HRshfWTTH
         XtH0S8vIDSLezyxPTAHVj+G8ibTU8PPMIwLZxuKu3a/Qe7f/20HcQ+QzJQtkXpd77jPN
         i2n3RGS3inQrDsJW5CsRhAMRcHrR7LsKyG3sQvEutSEQwEp0pBlQ637W9hjdb7IcoDj1
         89OOCSUXIv9nP/a0xqzQm3a8GD4F8FSocvYZm7LOP+X8rmS3l0G8K4ph9UCDBCBMiHdT
         QYtqdkIBmFwXpzjJ4Ys0+CZvEXhch3CK9cT3wiaJHxU1Tb4oSzrv6KBK9VZKqofCCfsH
         dxLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kr5ELmo2CFJUcJGuVutXQFJVTxMULdkBtNGc0x1punKykmutuZa
	RVYnu+YEq7zL70HE5WsTS+g=
X-Google-Smtp-Source: AMrXdXt3YeOBgn7AO9KcWqGJcADcvJ5XHUwYuqGYr8Ova937FFvikI7N2eCZGz3ROXwUyaAtHcnxZA==
X-Received: by 2002:a25:bd8f:0:b0:6f4:57a4:7838 with SMTP id f15-20020a25bd8f000000b006f457a47838mr1873560ybh.648.1674229136762;
        Fri, 20 Jan 2023 07:38:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:9d:b0:3fe:c52c:dd9a with SMTP id
 be29-20020a05690c009d00b003fec52cdd9als2901256ywb.4.-pod-prod-gmail; Fri, 20
 Jan 2023 07:38:56 -0800 (PST)
X-Received: by 2002:a81:151:0:b0:4eb:2cda:8b39 with SMTP id 78-20020a810151000000b004eb2cda8b39mr11537942ywb.3.1674229136131;
        Fri, 20 Jan 2023 07:38:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674229136; cv=none;
        d=google.com; s=arc-20160816;
        b=dyFaveRURIp5Jel4v3x2pHEUQVaa3/ON/GFT/oRZQ86m8PJScCOn+A+qWDrSXegPq3
         3LcV5PNIdp3UA2+AaWNyxxeAV4252vq0qyI0cZj+kneFm8anZkdklXW1qKXvQKXTDatP
         EJGB9L91dpPUOSmyl5nMxxb2Eksxh4o2W3GjJ0G2Vhl2RIP/lQkwp5l4GUkF5PVpxbml
         H5HNevMTuXfp378JuCY2Bj2Y4A9BhnEAsKJp8Ojfq5bX8Cbq1JWsVVIGFrOFgzfakfK4
         ISdO0Y7JmjoeC8n5rYGXemcjs9XfVqLbV31032GdhNgvClFubX6DNLiAHWuJ8McwRueO
         GF/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=gHZ4zxBKFj/78J0fghwgqaCjE6ht7Gwjai/lQVrZMf8=;
        b=w0Vq+soZY+M96OmV80lQZrRviN7AR3hFljEbdCKoc5efZ6Tx/dq/1bFXkeJeyKDLWd
         QLQHfgXf5vsQ4aRobK3O87J2L+wGea+xxCySLoWm5yz2wfLc6gp+Co9Vy45FONV+1t0a
         PY716rmV5FgLLVqgcKwmkhvokuAnwoQFXydmIfRVj8HvK6nzYpOoDJsJT4rR1KHS0FoR
         Iis7NkbKGWlAigi6H4aGblDEIeQib4y5svSCHCgT+94pTbRbMysQx8+9J+H7eqiiXVVM
         XO0u81Lxqx2ZaVkkCeEc934fY3iwDSEs6QJA8lXDbUJZhwZRQkybV1g7GEZC6rnMQSRC
         AYYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b="gzg/QqiL";
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=axboe@kernel.dk
Received: from mail-io1-xd2f.google.com (mail-io1-xd2f.google.com. [2607:f8b0:4864:20::d2f])
        by gmr-mx.google.com with ESMTPS id g1-20020ae9e101000000b006eeb0d15906si2869821qkm.6.2023.01.20.07.38.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Jan 2023 07:38:56 -0800 (PST)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::d2f as permitted sender) client-ip=2607:f8b0:4864:20::d2f;
Received: by mail-io1-xd2f.google.com with SMTP id h184so2596844iof.9
        for <kasan-dev@googlegroups.com>; Fri, 20 Jan 2023 07:38:56 -0800 (PST)
X-Received: by 2002:a5d:9e4d:0:b0:707:6808:45c0 with SMTP id i13-20020a5d9e4d000000b00707680845c0mr1239435ioi.1.1674229135632;
        Fri, 20 Jan 2023 07:38:55 -0800 (PST)
Received: from [192.168.1.94] ([96.43.243.2])
        by smtp.gmail.com with ESMTPSA id t19-20020a056602141300b006e01740c3b6sm13476398iov.2.2023.01.20.07.38.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Jan 2023 07:38:55 -0800 (PST)
Message-ID: <d0f3cc26-959a-4e63-a840-5c3429932185@kernel.dk>
Date: Fri, 20 Jan 2023 08:38:54 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH] io_uring: Enable KASAN for request cache
Content-Language: en-US
To: Pavel Begunkov <asml.silence@gmail.com>, Breno Leitao
 <leitao@debian.org>, io-uring@vger.kernel.org
Cc: kasan-dev@googlegroups.com, leit@fb.com, linux-kernel@vger.kernel.org
References: <20230118155630.2762921-1-leitao@debian.org>
 <a0f75aa2-34dc-e3a8-c9fe-11f88412ef93@gmail.com>
From: Jens Axboe <axboe@kernel.dk>
In-Reply-To: <a0f75aa2-34dc-e3a8-c9fe-11f88412ef93@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112
 header.b="gzg/QqiL";       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=axboe@kernel.dk
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

On 1/20/23 8:09=E2=80=AFAM, Pavel Begunkov wrote:
> On 1/18/23 15:56, Breno Leitao wrote:
>> Every io_uring request is represented by struct io_kiocb, which is
>> cached locally by io_uring (not SLAB/SLUB) in the list called
>> submit_state.freelist. This patch simply enabled KASAN for this free
>> list.
>>
>> This list is initially created by KMEM_CACHE, but later, managed by
>> io_uring. This patch basically poisons the objects that are not used
>> (i.e., they are the free list), and unpoisons it when the object is
>> allocated/removed from the list.
>>
>> Touching these poisoned objects while in the freelist will cause a KASAN
>> warning.
>=20
> Doesn't apply cleanly to for-6.3/io_uring, but otherwise looks good
>=20
> Reviewed-by: Pavel Begunkov <asml.silence@gmail.com>

I ran testing on this yesterday and noticed the same thing, just a
trivial fuzz reject. I can fix it up while applying. Thanks for
reviewing!

--=20
Jens Axboe


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d0f3cc26-959a-4e63-a840-5c3429932185%40kernel.dk.
