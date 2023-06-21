Return-Path: <kasan-dev+bncBCAP7WGUVIKBBIE6ZSSAMGQEP3JENJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5282D738805
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jun 2023 16:54:26 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-55e54605e67sf1995892eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jun 2023 07:54:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687359265; cv=pass;
        d=google.com; s=arc-20160816;
        b=aMtV2+t5dUuJu0yoXI1YU4k/2JfV97kekTfdbNPzSKqOE8jYJ8uxhMPLSyKNDrByH5
         hWxyy+hMil6U97lsedmwsOf695vqkSnt1rMQajpYDuCTZe2XwCdWOVUAKDQDdNA1ve58
         xFNf+UXH/tKsXk8KYESoKOQlwaCJe65t9Om+qI4vjzMmyL8SQRh7Q+Gw9JO5WDNdiV32
         oTFFsPDNLSOnPbpf9xOabvp3BDiLWMzhtkhu1Rcb8Iswwdzejm/yeX3YVedxpyHpAcnb
         W2h1gXNBc8RcKBiVqVnD6FO3UjfmgApZgtCcXxClDw2XVnaE+tQeoPzHcwHMbnshggXI
         GQzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=7Jp9Rde2YgGzuB9g8Cl4XfPD2O70K7OPD5CXA1xR2oA=;
        b=k1jexXhmR4nbV6UdHQpF+pWogHQ4XqyAj0SUQKwnJ6hVE/DASyV7Z+gkcgJg0efV3L
         moKhOHIP85p5g4YlhrYVNhskXqOPRoXE1r+xDTRJRxUqWpf+cnsVyVactL/1sLvCgktD
         w/zRiAx3oUCAEi+UDDBF9dlJimxSRydJFoqnciqCYYeeA+AIeK8MweYws3hdOhvcx6ro
         RR9uAG+QM0DS4NDWfEgczWpeHWXR0Mo7//DodCetNM3FUXApzs8PlSvdJpyS9iAvJVdD
         D1VCOKWqEjd2hTcvP6yQ8NP154gzAVK6TdXfOOoJCTsZ/gmdG7/HWIoVKfUh6BWeY6Ka
         h8fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687359265; x=1689951265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7Jp9Rde2YgGzuB9g8Cl4XfPD2O70K7OPD5CXA1xR2oA=;
        b=q1vI0T3xejxzFTfbPbO7lITy4TTpNPR288bE2f35nIvEg2yzPEHwofmk1EfPUra8d4
         SGyWW8C8yp40Wg5cQFIXT8deZYxhP6zYndhw33Qmdz7CesaCU1M3VodZUXHsiGc+mzul
         W/7SPB0z7iibTihxTBzH+Eth77AjydQV7l05wS5p/h3QTSxRqJvkMbPHo5rNj/s6b+td
         GXi9nxB91Sg5R24hUl5cS+3ARWX1wVijRHf8Y08wo0QL6vBPOoZPy/UcFCDsjzlO0d3v
         2csQN/T3Z3MXZ0K0G5JNe9SaNHCktUEO0ZYhkgXkQykhVpN582zRNDNS4d6dLMPDnfDZ
         j7nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687359265; x=1689951265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7Jp9Rde2YgGzuB9g8Cl4XfPD2O70K7OPD5CXA1xR2oA=;
        b=H8gn2f8pepmZPvFceZQEJ9iYDSYsR9Z3JI9hec9u06hRYqlrg22SKAEEsw+dsTdL38
         aKS3wu2FcRYqxoC6OYg5AR8eOK5v8QS5n6Q6wbIjkHsJNt/49HRFTxlODXrP3+x+L6Wr
         WGa22AmHF1BJsJzMxyk9q5iNoUgZvWLZHbPakZVYTsl7jXS68t2AuXJqKrmh+BE8guWf
         Gn0rxsGNcjh3EJZ+i9pzAZ2DyVOmufS+nCQjs9p67d+v6hghcJA9Ib/BmIeErK5nni0k
         hwQ2DZBVRHi9ObWnYK5yEANykHrWs0wb6WGAC8JDK3YATIxcc0+bsJl3sJEYBA8oZK3U
         7THw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwihuksGeYi7CUmaeZI/JiyI9tD8/OyknM/RDeRoP2kEu6g5Vw6
	OHYpkKePmhuvX9FBajuVo6Y=
X-Google-Smtp-Source: ACHHUZ7q5TU9du/ezoG0rxR97nnxRTpo5W2Cn+ETXNwLcEbUHTQMNpZVWAOV1ooChWD7Hw5HEl7WHQ==
X-Received: by 2002:a4a:ce84:0:b0:557:ccb2:7fff with SMTP id f4-20020a4ace84000000b00557ccb27fffmr8156420oos.1.1687359264894;
        Wed, 21 Jun 2023 07:54:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:a2c6:0:b0:560:9ea5:bcd2 with SMTP id r6-20020a4aa2c6000000b005609ea5bcd2ls969350ool.2.-pod-prod-06-us;
 Wed, 21 Jun 2023 07:54:24 -0700 (PDT)
X-Received: by 2002:aca:7c5:0:b0:398:1045:17ed with SMTP id 188-20020aca07c5000000b00398104517edmr12204322oih.54.1687359264231;
        Wed, 21 Jun 2023 07:54:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687359264; cv=none;
        d=google.com; s=arc-20160816;
        b=yqhV2FLnLjIkzf+ihEAzL4BlACQ9csqmAsOM/BszEsixvcnNVtzzWoC3gVP861n/hn
         3AOschhaN9rDI4QOgGS9u5/6ygyh5KceO6T9PADreFRQP5qUt293baIN39wGlO7Hhg5J
         ooDY8gijePKD3cI3XX3giK5Oa6vqWqZHIajU2vWYic0j9kmxtJoOs0qbRuke2lTrGvbT
         j8YT99UdnKRLT3GbDrwzvmbnuzxRcUs5U6dNFckhaDpMyQqGpgqtoTkwZzCcRyr2th9H
         hDZD/qsKKA2fNj2s8RQ6Y+Zt9HhziS9R/lTjhgDrRcOo75vVxH5HjcXHo8QIWJgn1EnY
         hgNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=EMhwbdm4l8sElgvipVJ65tQSOkwb/k9noZBGTNAhy1E=;
        b=rPxWmK4+CBKurPm7+BRiprv1eoMzoY6Nbl3COpQnw1nZUWUErWeraX1zv33s+q0Y8y
         1GPcGkXIPbmhok4E3mNvysisto3fvNhAXl4gpB40eGffGnsJbyW3uLVZdsmDM46u2saz
         LvwRC0lTPovTCw3AvcwXdnFw6eLzpLamRrxblQjSQPubbH2VSTxz1jCMK97eS+AaKuML
         QgEx45emJIkkP5cAs23XigmAxpmVd7UZ31v1mwhQ2BeO90BjPIQCyS6/8TAEIwyePASa
         Z2HZeesPC6yfqFRJtx2nj0fWqlYLC2Tcbz8VJYzB3L+XG+6bpOra6p0XA2K5HvDoSoTe
         RL2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id u17-20020a056808115100b0039ee179478csi480858oiu.0.2023.06.21.07.54.23
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jun 2023 07:54:24 -0700 (PDT)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav111.sakura.ne.jp (fsav111.sakura.ne.jp [27.133.134.238])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 35LEs9Sw088747;
	Wed, 21 Jun 2023 23:54:09 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav111.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav111.sakura.ne.jp);
 Wed, 21 Jun 2023 23:54:09 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav111.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 35LEs9t2088743
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Wed, 21 Jun 2023 23:54:09 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <50860b89-6a7d-120d-a1e4-017a3e3c13a7@I-love.SAKURA.ne.jp>
Date: Wed, 21 Jun 2023 23:54:08 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.12.0
Subject: Re: [PATCH v3] lib/stackdepot: fix gfp flags manipulation in
 __stack_depot_save()
Content-Language: en-US
To: Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>
Cc: "Huang, Ying" <ying.huang@intel.com>,
        syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
        syzkaller-bugs@googlegroups.com,
        Mel Gorman <mgorman@techsingularity.net>,
        Vlastimil Babka <vbabka@suse.cz>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin
 <ryabinin.a.a@gmail.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
        linux-mm <linux-mm@kvack.org>
References: <000000000000cef3a005fc1bcc80@google.com>
 <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
 <656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp>
 <87353gx7wd.fsf@yhuang6-desk2.ccr.corp.intel.com>
 <CAG_fn=UTTbkGeOX0teGcNOeobtgV=mfGOefZpV-NTN4Ouus7xA@mail.gmail.com>
 <20230609153124.11905393c03660369f4f5997@linux-foundation.org>
 <19d6c965-a9cf-16a5-6537-a02823d67c0a@I-love.SAKURA.ne.jp>
 <CAG_fn=XBBVBj9VcFkirMNj9sQOHvx2Q12o9esDkgPB0BP33DKg@mail.gmail.com>
 <34aab39f-10c0-bb72-832b-d44a8ef96c2e@I-love.SAKURA.ne.jp>
 <CAG_fn=X4qxdbfm-8vcbN2F-qr-cCPBG+1884Hnw5CXL4OgRT8Q@mail.gmail.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <CAG_fn=X4qxdbfm-8vcbN2F-qr-cCPBG+1884Hnw5CXL4OgRT8Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2023/06/21 23:42, Alexander Potapenko wrote:
>> "[PATCH] kasan,kmsan: remove __GFP_KSWAPD_RECLAIM usage from kasan/kmsan"
>> looks the better.
>>
> 
> I agree, let's go for it.
> Sorry for the trouble.
> 

No problem. :-)

Andrew, please take "[PATCH] kasan,kmsan: remove __GFP_KSWAPD_RECLAIM usage from kasan/kmsan"
at https://lkml.kernel.org/r/656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp
with "Reviewed-by: "Huang, Ying" <ying.huang@intel.com>" added.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/50860b89-6a7d-120d-a1e4-017a3e3c13a7%40I-love.SAKURA.ne.jp.
