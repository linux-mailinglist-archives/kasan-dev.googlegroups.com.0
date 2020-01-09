Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBV4D3TYAKGQE6ZO63HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 23D611356FF
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 11:35:04 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id z15sf2745311wrw.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 02:35:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578566103; cv=pass;
        d=google.com; s=arc-20160816;
        b=ovLNKh5AjDLLWGaq//bsOC072PrddYcNVjDYzCBSCwbCfsc4FECRcACupjvf1QNHi8
         iSTw7DLf/QvMNyEhV0hySpZJsKhx9tFl/UEJ10ptp93Tp2BwO/9C9NB9YzEC4yUsNl8u
         3MsjrwnPyUws3ydk7LrivUrD+Em4wiPVJvYe8kTTF+ClxJsj3+hy0AGpNrMDfMrzYWA7
         gm8UNC98b/6z5LrmsGc7BDNsU2vYqyv7RERrVzqzVwNg2evy9xhsH33cOQKelaJUP3aS
         /8108D3V5sRMv2n+fyMpMSLK1xqx8lUqltfs5dpuFnFHucXuRJmCiCG20Gz1ptVDQYnX
         ISqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:sender:dkim-signature;
        bh=JgtyEh6dmjGsHx+rtHjJ4BEIeS8zstmLrL0Ql4l4ACU=;
        b=vxdcME/bgnDeO9FbuGTznzMuTWO1tUOunvp+6OUBiLmNnzxNCEvqodw28M1IKrnPDd
         vxTySaw099o/KCiRQLNXOoS9MAcFPnrrn2S4NlJx2m5Xf9ylUJf0WPqRzLCB+SToDF0w
         Ta5BB9bH/0SohRMw5LLOyr4aRLPS2iIYnMCbF4oHGHrQgEwvhTjDnrGedrDF7MnOlMHk
         qm8cdf3675j45e4QH1zKu9UH9+QmZzNSWRecHLt2iiWJNqTp15meFEzuU3mjZ2hl1mnD
         pgHuCPDKX5Q/3rNd8HrQJk5dsObHdCFhhRrMO/Qa7ariAbLCDnaw4fhAWwAXUbGw2Vgv
         X3hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JgtyEh6dmjGsHx+rtHjJ4BEIeS8zstmLrL0Ql4l4ACU=;
        b=MjdJxsBooO3Pn5Zf/+yYufishzFr5DwyfPDpUSMVjkZocDm9JVUD7+CiNbWcLvIPXf
         6SNr7kN4woalDTpeul0y4LTgRAWZ/YXIJBbpiCGbSLCi5TFZ8fv5+oVW+yI+dhLOLK+C
         9fphfyt2wyRfy0hw3Fz9qA4sQWhglTwrivYZi2c80CV2JrIOYwQdl9NNiTOxJ3NEnTzS
         RDVcyXVaYspMfwQQQm2T4CrCGVKnqkFOpB3yBIV3pC5lW9sg/syVRJlUjhUaK5ZguD51
         cq7M3NwxJ95r78KxNM7UVGJfe1K3FJUwR7f8mrwoWFfTVc71DtGBD/JaGqw162aUX2UK
         YgTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JgtyEh6dmjGsHx+rtHjJ4BEIeS8zstmLrL0Ql4l4ACU=;
        b=IKs+7clPMpd4bvCCvWmcNPP07DII8srJbUcIholDVwRtzDSduoDWUevNOYstKg25Uu
         qbr4ji4ovvzam2QWTYShxRkFaJT7YoxcItU/qBgow5NOmjtkpK3yQyYlQ6JDbrlQyEsr
         yp1rjfYpbFhpi3KYwzWlG3MFAkpvwmTNuzJDWWqIJH8rgvE4xQX2qQbTwE9B7Bctg5HK
         otb2CecJ3KRzAR9vO0F5GWLFqpuNlOqQh+3VQJzYVbfelD2jmt2tlphTlItxhgSG1Yqk
         bI0N33KQj6GU1ItL51cIzu1Zzyug86oJi3dLIeHZ0VG+wwsajMdYi9yJKOAESX/7ajfO
         sNPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUxzGwih4Ca857I8PeGL60MrXL0Soc8JTIQlgIzEUbKp/HzDPvd
	R6YfoaJqWdZVyfHfnnIQvmo=
X-Google-Smtp-Source: APXvYqx2BDkX0iJpcWo17qS5Ig6KieTMl3Wc2LeLJnLaDN2xsXpONJOm0uAkRqe/lTMQRck4tFdCag==
X-Received: by 2002:adf:f18b:: with SMTP id h11mr9797354wro.56.1578566103793;
        Thu, 09 Jan 2020 02:35:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4682:: with SMTP id u2ls469397wrq.14.gmail; Thu, 09 Jan
 2020 02:35:03 -0800 (PST)
X-Received: by 2002:adf:fc0c:: with SMTP id i12mr10823256wrr.74.1578566103127;
        Thu, 09 Jan 2020 02:35:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578566103; cv=none;
        d=google.com; s=arc-20160816;
        b=uwE2n2uF9HLd4y8nKVR01hgmbPysnrKaEIwd6+Q8U1ZvERpXZ6E2e9UWpPPUpAs0a1
         1ZcjLSrE9/jlbP1tFZfRE7/SWrfiGA9ENpw4qaZDFPOMzdeDytfnOX+gBkuVacmgORBF
         araNIzVfLF+a1lKnvIYcfUZ88IhS/fkNszRik8cAvAChnRTQdGk1SXGz9WwpfqOuhYiQ
         XRGczBN2i80d70N3whRInU0cGzeN0dFM7RVrh4i3qESduFQCl3nV3IiuNUmavlpuyS/M
         9jxXW9eDm/GCb38a7z6lNcRd8SINLkVXWhtSOrThqxcKyS8Gv2QbVPH5IVWVvIYbGLCo
         hm6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject;
        bh=2iPNRIJ74fD69S6v5SaGLDOmgw5kIDhvLmz7yM1pKrY=;
        b=lGakG7H4V+3+106x/2tKB6IyvhO37CW67gmaLVPKf0XTMkOVf6wmh68nKG3AVED/Y8
         IAR965bRdaqpAwPZYwFVqfE5loYu69hUHQ+6W4UukJqAq2qx2cBONn7LC2m+lylgCTp8
         2qQUpLXsd15brbIyw9irFZMuGHeZv5M+dXBBV/26w4jvmSjEGanCf8a7PRVSMKvoQu6u
         /UjSZlazFnt5LvNBOpxHyA18IwZuUJtfL6zCkhysRAPMdCsXJWOQufr93xb/V9S4Vrvu
         KAPZZuX+yKBf5/Po3fZiJYH0fOaf7mhS2jGqhMj5yTs+0ADBBA4FaPMOLxxIPqruYUrf
         IRcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id x5si114108wmk.1.2020.01.09.02.35.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jan 2020 02:35:03 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 08F836A048;
	Thu,  9 Jan 2020 10:33:26 +0000 (UTC)
Subject: Re: [PATCH v1 4/4] xen/netback: Fix grant copy across page boundary
 with KASAN
To: Sergey Dyasli <sergey.dyasli@citrix.com>, xen-devel@lists.xen.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Boris Ostrovsky <boris.ostrovsky@oracle.com>, Juergen Gross
 <jgross@suse.com>, Stefano Stabellini <sstabellini@kernel.org>,
 George Dunlap <george.dunlap@citrix.com>,
 Ross Lagerwall <ross.lagerwall@citrix.com>,
 Andrew Morton <akpm@linux-foundation.org>, Wei Liu <wei.liu@kernel.org>,
 Paul Durrant <paul@xen.org>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
 <20200108152100.7630-5-sergey.dyasli@citrix.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; prefer-encrypt=mutual; keydata=
 mQINBFZdmxYBEADsw/SiUSjB0dM+vSh95UkgcHjzEVBlby/Fg+g42O7LAEkCYXi/vvq31JTB
 KxRWDHX0R2tgpFDXHnzZcQywawu8eSq0LxzxFNYMvtB7sV1pxYwej2qx9B75qW2plBs+7+YB
 87tMFA+u+L4Z5xAzIimfLD5EKC56kJ1CsXlM8S/LHcmdD9Ctkn3trYDNnat0eoAcfPIP2OZ+
 9oe9IF/R28zmh0ifLXyJQQz5ofdj4bPf8ecEW0rhcqHfTD8k4yK0xxt3xW+6Exqp9n9bydiy
 tcSAw/TahjW6yrA+6JhSBv1v2tIm+itQc073zjSX8OFL51qQVzRFr7H2UQG33lw2QrvHRXqD
 Ot7ViKam7v0Ho9wEWiQOOZlHItOOXFphWb2yq3nzrKe45oWoSgkxKb97MVsQ+q2SYjJRBBH4
 8qKhphADYxkIP6yut/eaj9ImvRUZZRi0DTc8xfnvHGTjKbJzC2xpFcY0DQbZzuwsIZ8OPJCc
 LM4S7mT25NE5kUTG/TKQCk922vRdGVMoLA7dIQrgXnRXtyT61sg8PG4wcfOnuWf8577aXP1x
 6mzw3/jh3F+oSBHb/GcLC7mvWreJifUL2gEdssGfXhGWBo6zLS3qhgtwjay0Jl+kza1lo+Cv
 BB2T79D4WGdDuVa4eOrQ02TxqGN7G0Biz5ZLRSFzQSQwLn8fbwARAQABtCBWbGFzdGltaWwg
 QmFia2EgPHZiYWJrYUBzdXNlLmN6PokCVAQTAQoAPgIbAwULCQgHAwUVCgkICwUWAgMBAAIe
 AQIXgBYhBKlA1DSZLC6OmRA9UCJPp+fMgqZkBQJcbbyGBQkH8VTqAAoJECJPp+fMgqZkpGoP
 /1jhVihakxw1d67kFhPgjWrbzaeAYOJu7Oi79D8BL8Vr5dmNPygbpGpJaCHACWp+10KXj9yz
 fWABs01KMHnZsAIUytVsQv35DMMDzgwVmnoEIRBhisMYOQlH2bBn/dqBjtnhs7zTL4xtqEcF
 1hoUFEByMOey7gm79utTk09hQE/Zo2x0Ikk98sSIKBETDCl4mkRVRlxPFl4O/w8dSaE4eczH
 LrKezaFiZOv6S1MUKVKzHInonrCqCNbXAHIeZa3JcXCYj1wWAjOt9R3NqcWsBGjFbkgoKMGD
 usiGabetmQjXNlVzyOYdAdrbpVRNVnaL91sB2j8LRD74snKsV0Wzwt90YHxDQ5z3M75YoIdl
 byTKu3BUuqZxkQ/emEuxZ7aRJ1Zw7cKo/IVqjWaQ1SSBDbZ8FAUPpHJxLdGxPRN8Pfw8blKY
 8mvLJKoF6i9T6+EmlyzxqzOFhcc4X5ig5uQoOjTIq6zhLO+nqVZvUDd2Kz9LMOCYb516cwS/
 Enpi0TcZ5ZobtLqEaL4rupjcJG418HFQ1qxC95u5FfNki+YTmu6ZLXy+1/9BDsPuZBOKYpUm
 3HWSnCS8J5Ny4SSwfYPH/JrtberWTcCP/8BHmoSpS/3oL3RxrZRRVnPHFzQC6L1oKvIuyXYF
 rkybPXYbmNHN+jTD3X8nRqo+4Qhmu6SHi3VquQENBFsZNQwBCACuowprHNSHhPBKxaBX7qOv
 KAGCmAVhK0eleElKy0sCkFghTenu1sA9AV4okL84qZ9gzaEoVkgbIbDgRbKY2MGvgKxXm+kY
 n8tmCejKoeyVcn9Xs0K5aUZiDz4Ll9VPTiXdf8YcjDgeP6/l4kHb4uSW4Aa9ds0xgt0gP1Xb
 AMwBlK19YvTDZV5u3YVoGkZhspfQqLLtBKSt3FuxTCU7hxCInQd3FHGJT/IIrvm07oDO2Y8J
 DXWHGJ9cK49bBGmK9B4ajsbe5GxtSKFccu8BciNluF+BqbrIiM0upJq5Xqj4y+Xjrpwqm4/M
 ScBsV0Po7qdeqv0pEFIXKj7IgO/d4W2bABEBAAGJA3IEGAEKACYWIQSpQNQ0mSwujpkQPVAi
 T6fnzIKmZAUCWxk1DAIbAgUJA8JnAAFACRAiT6fnzIKmZMB0IAQZAQoAHRYhBKZ2GgCcqNxn
 k0Sx9r6Fd25170XjBQJbGTUMAAoJEL6Fd25170XjDBUH/2jQ7a8g+FC2qBYxU/aCAVAVY0NE
 YuABL4LJ5+iWwmqUh0V9+lU88Cv4/G8fWwU+hBykSXhZXNQ5QJxyR7KWGy7LiPi7Cvovu+1c
 9Z9HIDNd4u7bxGKMpn19U12ATUBHAlvphzluVvXsJ23ES/F1c59d7IrgOnxqIcXxr9dcaJ2K
 k9VP3TfrjP3g98OKtSsyH0xMu0MCeyewf1piXyukFRRMKIErfThhmNnLiDbaVy6biCLx408L
 Mo4cCvEvqGKgRwyckVyo3JuhqreFeIKBOE1iHvf3x4LU8cIHdjhDP9Wf6ws1XNqIvve7oV+w
 B56YWoalm1rq00yUbs2RoGcXmtX1JQ//aR/paSuLGLIb3ecPB88rvEXPsizrhYUzbe1TTkKc
 4a4XwW4wdc6pRPVFMdd5idQOKdeBk7NdCZXNzoieFntyPpAq+DveK01xcBoXQ2UktIFIsXey
 uSNdLd5m5lf7/3f0BtaY//f9grm363NUb9KBsTSnv6Vx7Co0DWaxgC3MFSUhxzBzkJNty+2d
 10jvtwOWzUN+74uXGRYSq5WefQWqqQNnx+IDb4h81NmpIY/X0PqZrapNockj3WHvpbeVFAJ0
 9MRzYP3x8e5OuEuJfkNnAbwRGkDy98nXW6fKeemREjr8DWfXLKFWroJzkbAVmeIL0pjXATxr
 +tj5JC0uvMrrXefUhXTo0SNoTsuO/OsAKOcVsV/RHHTwCDR2e3W8mOlA3QbYXsscgjghbuLh
 J3oTRrOQa8tUXWqcd5A0+QPo5aaMHIK0UAthZsry5EmCY3BrbXUJlt+23E93hXQvfcsmfi0N
 rNh81eknLLWRYvMOsrbIqEHdZBT4FHHiGjnck6EYx/8F5BAZSodRVEAgXyC8IQJ+UVa02QM5
 D2VL8zRXZ6+wARKjgSrW+duohn535rG/ypd0ctLoXS6dDrFokwTQ2xrJiLbHp9G+noNTHSan
 ExaRzyLbvmblh3AAznb68cWmM3WVkceWACUalsoTLKF1sGrrIBj5updkKkzbKOq5gcC5AQ0E
 Wxk1NQEIAJ9B+lKxYlnKL5IehF1XJfknqsjuiRzj5vnvVrtFcPlSFL12VVFVUC2tT0A1Iuo9
 NAoZXEeuoPf1dLDyHErrWnDyn3SmDgb83eK5YS/K363RLEMOQKWcawPJGGVTIRZgUSgGusKL
 NuZqE5TCqQls0x/OPljufs4gk7E1GQEgE6M90Xbp0w/r0HB49BqjUzwByut7H2wAdiNAbJWZ
 F5GNUS2/2IbgOhOychHdqYpWTqyLgRpf+atqkmpIJwFRVhQUfwztuybgJLGJ6vmh/LyNMRr8
 J++SqkpOFMwJA81kpjuGR7moSrUIGTbDGFfjxmskQV/W/c25Xc6KaCwXah3OJ40AEQEAAYkC
 PAQYAQoAJhYhBKlA1DSZLC6OmRA9UCJPp+fMgqZkBQJbGTU1AhsMBQkDwmcAAAoJECJPp+fM
 gqZkPN4P/Ra4NbETHRj5/fM1fjtngt4dKeX/6McUPDIRuc58B6FuCQxtk7sX3ELs+1+w3eSV
 rHI5cOFRSdgw/iKwwBix8D4Qq0cnympZ622KJL2wpTPRLlNaFLoe5PkoORAjVxLGplvQIlhg
 miljQ3R63ty3+MZfkSVsYITlVkYlHaSwP2t8g7yTVa+q8ZAx0NT9uGWc/1Sg8j/uoPGrctml
 hFNGBTYyPq6mGW9jqaQ8en3ZmmJyw3CHwxZ5FZQ5qc55xgshKiy8jEtxh+dgB9d8zE/S/UGI
 E99N/q+kEKSgSMQMJ/CYPHQJVTi4YHh1yq/qTkHRX+ortrF5VEeDJDv+SljNStIxUdroPD29
 2ijoaMFTAU+uBtE14UP5F+LWdmRdEGS1Ah1NwooL27uAFllTDQxDhg/+LJ/TqB8ZuidOIy1B
 xVKRSg3I2m+DUTVqBy7Lixo73hnW69kSjtqCeamY/NSu6LNP+b0wAOKhwz9hBEwEHLp05+mj
 5ZFJyfGsOiNUcMoO/17FO4EBxSDP3FDLllpuzlFD7SXkfJaMWYmXIlO0jLzdfwfcnDzBbPwO
 hBM8hvtsyq8lq8vJOxv6XD6xcTtj5Az8t2JjdUX6SF9hxJpwhBU0wrCoGDkWp4Bbv6jnF7zP
 Nzftr4l8RuJoywDIiJpdaNpSlXKpj/K6KrnyAI/joYc7
Message-ID: <26c43c43-b303-938c-2f26-8e0144159e29@suse.cz>
Date: Thu, 9 Jan 2020 11:33:25 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.3.1
MIME-Version: 1.0
In-Reply-To: <20200108152100.7630-5-sergey.dyasli@citrix.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/8/20 4:21 PM, Sergey Dyasli wrote:
> From: Ross Lagerwall <ross.lagerwall@citrix.com>
> 
> When KASAN (or SLUB_DEBUG) is turned on, the normal expectation that
> allocations are aligned to the next power of 2 of the size does not
> hold.

Hmm, really? They should after 59bb47985c1d ("mm, sl[aou]b: guarantee
natural alignment for kmalloc(power-of-two)"), i.e. since 5.4.

But actually the guarantee is only for precise power of two sizes given
to kmalloc(). Allocations of sizes that end up using the 96 or 192 bytes
kmalloc cache have no such guarantee. But those might then cross page
boundary also without SLUB_DEBUG.

> Therefore, handle grant copies that cross page boundaries.
> 
> Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
> ---
> RFC --> v1:
> - Added BUILD_BUG_ON to the netback patch
> - xenvif_idx_release() now located outside the loop
> 
> CC: Wei Liu <wei.liu@kernel.org>
> CC: Paul Durrant <paul@xen.org>
> ---
>  drivers/net/xen-netback/common.h  |  2 +-
>  drivers/net/xen-netback/netback.c | 59 +++++++++++++++++++++++++------
>  2 files changed, 49 insertions(+), 12 deletions(-)
> 
> diff --git a/drivers/net/xen-netback/common.h b/drivers/net/xen-netback/common.h
> index 05847eb91a1b..e57684415edd 100644
> --- a/drivers/net/xen-netback/common.h
> +++ b/drivers/net/xen-netback/common.h
> @@ -155,7 +155,7 @@ struct xenvif_queue { /* Per-queue data for xenvif */
>  	struct pending_tx_info pending_tx_info[MAX_PENDING_REQS];
>  	grant_handle_t grant_tx_handle[MAX_PENDING_REQS];
>  
> -	struct gnttab_copy tx_copy_ops[MAX_PENDING_REQS];
> +	struct gnttab_copy tx_copy_ops[MAX_PENDING_REQS * 2];
>  	struct gnttab_map_grant_ref tx_map_ops[MAX_PENDING_REQS];
>  	struct gnttab_unmap_grant_ref tx_unmap_ops[MAX_PENDING_REQS];
>  	/* passed to gnttab_[un]map_refs with pages under (un)mapping */
> diff --git a/drivers/net/xen-netback/netback.c b/drivers/net/xen-netback/netback.c
> index 0020b2e8c279..33b8f8d043e6 100644
> --- a/drivers/net/xen-netback/netback.c
> +++ b/drivers/net/xen-netback/netback.c
> @@ -320,6 +320,7 @@ static int xenvif_count_requests(struct xenvif_queue *queue,
>  
>  struct xenvif_tx_cb {
>  	u16 pending_idx;
> +	u8 copies;
>  };
>  
>  #define XENVIF_TX_CB(skb) ((struct xenvif_tx_cb *)(skb)->cb)
> @@ -439,6 +440,7 @@ static int xenvif_tx_check_gop(struct xenvif_queue *queue,
>  {
>  	struct gnttab_map_grant_ref *gop_map = *gopp_map;
>  	u16 pending_idx = XENVIF_TX_CB(skb)->pending_idx;
> +	u8 copies = XENVIF_TX_CB(skb)->copies;
>  	/* This always points to the shinfo of the skb being checked, which
>  	 * could be either the first or the one on the frag_list
>  	 */
> @@ -450,23 +452,26 @@ static int xenvif_tx_check_gop(struct xenvif_queue *queue,
>  	int nr_frags = shinfo->nr_frags;
>  	const bool sharedslot = nr_frags &&
>  				frag_get_pending_idx(&shinfo->frags[0]) == pending_idx;
> -	int i, err;
> +	int i, err = 0;
>  
> -	/* Check status of header. */
> -	err = (*gopp_copy)->status;
> -	if (unlikely(err)) {
> -		if (net_ratelimit())
> -			netdev_dbg(queue->vif->dev,
> +	while (copies) {
> +		/* Check status of header. */
> +		int newerr = (*gopp_copy)->status;
> +		if (unlikely(newerr)) {
> +			if (net_ratelimit())
> +				netdev_dbg(queue->vif->dev,
>  				   "Grant copy of header failed! status: %d pending_idx: %u ref: %u\n",
>  				   (*gopp_copy)->status,
>  				   pending_idx,
>  				   (*gopp_copy)->source.u.ref);
> -		/* The first frag might still have this slot mapped */
> -		if (!sharedslot)
> -			xenvif_idx_release(queue, pending_idx,
> -					   XEN_NETIF_RSP_ERROR);
> +			err = newerr;
> +		}
> +		(*gopp_copy)++;
> +		copies--;
>  	}
> -	(*gopp_copy)++;
> +	/* The first frag might still have this slot mapped */
> +	if (unlikely(err) && !sharedslot)
> +		xenvif_idx_release(queue, pending_idx, XEN_NETIF_RSP_ERROR);
>  
>  check_frags:
>  	for (i = 0; i < nr_frags; i++, gop_map++) {
> @@ -910,6 +915,7 @@ static void xenvif_tx_build_gops(struct xenvif_queue *queue,
>  			xenvif_tx_err(queue, &txreq, extra_count, idx);
>  			break;
>  		}
> +		XENVIF_TX_CB(skb)->copies = 0;
>  
>  		skb_shinfo(skb)->nr_frags = ret;
>  		if (data_len < txreq.size)
> @@ -933,6 +939,7 @@ static void xenvif_tx_build_gops(struct xenvif_queue *queue,
>  						   "Can't allocate the frag_list skb.\n");
>  				break;
>  			}
> +			XENVIF_TX_CB(nskb)->copies = 0;
>  		}
>  
>  		if (extras[XEN_NETIF_EXTRA_TYPE_GSO - 1].type) {
> @@ -990,6 +997,31 @@ static void xenvif_tx_build_gops(struct xenvif_queue *queue,
>  
>  		queue->tx_copy_ops[*copy_ops].len = data_len;
>  		queue->tx_copy_ops[*copy_ops].flags = GNTCOPY_source_gref;
> +		XENVIF_TX_CB(skb)->copies++;
> +
> +		if (offset_in_page(skb->data) + data_len > XEN_PAGE_SIZE) {
> +			unsigned int extra_len = offset_in_page(skb->data) +
> +					     data_len - XEN_PAGE_SIZE;
> +
> +			queue->tx_copy_ops[*copy_ops].len -= extra_len;
> +			(*copy_ops)++;
> +
> +			queue->tx_copy_ops[*copy_ops].source.u.ref = txreq.gref;
> +			queue->tx_copy_ops[*copy_ops].source.domid =
> +				queue->vif->domid;
> +			queue->tx_copy_ops[*copy_ops].source.offset =
> +				txreq.offset + data_len - extra_len;
> +
> +			queue->tx_copy_ops[*copy_ops].dest.u.gmfn =
> +				virt_to_gfn(skb->data + data_len - extra_len);
> +			queue->tx_copy_ops[*copy_ops].dest.domid = DOMID_SELF;
> +			queue->tx_copy_ops[*copy_ops].dest.offset = 0;
> +
> +			queue->tx_copy_ops[*copy_ops].len = extra_len;
> +			queue->tx_copy_ops[*copy_ops].flags = GNTCOPY_source_gref;
> +
> +			XENVIF_TX_CB(skb)->copies++;
> +		}
>  
>  		(*copy_ops)++;
>  
> @@ -1674,5 +1706,10 @@ static void __exit netback_fini(void)
>  }
>  module_exit(netback_fini);
>  
> +static void __init __maybe_unused build_assertions(void)
> +{
> +	BUILD_BUG_ON(sizeof(struct xenvif_tx_cb) > 48);
> +}
> +
>  MODULE_LICENSE("Dual BSD/GPL");
>  MODULE_ALIAS("xen-backend:vif");
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/26c43c43-b303-938c-2f26-8e0144159e29%40suse.cz.
