Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBE4JWLWAKGQE6P5OPEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D427BEE6D
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 11:27:48 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id l9sf948854edi.8
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 02:27:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569490067; cv=pass;
        d=google.com; s=arc-20160816;
        b=y2UFQY2wNY+OLTEOKxegBy9q9BQQM18HEZiTYVQKRu5FE5CNNeGtF3e3eHSAfZL3s8
         LFniPH7U9uaAzdlozYxZqFFlZ9nr69NDfMfp2SV54kR6aXWmrVQTiG2YbP4Fb/gRHK5o
         pLHP8w2AFluySb/azF6Gg2vUSgJREJ7XtNCVGlH7DUirZXdN39K4PQ75dQGKLH6sVCPh
         iJ6ynFntsSnFZuleOQsb/nTyIpCFDf76ifmZJPfLNUntV/XtmVmE/8SQxn4Qw+Zmdsk/
         OC/ShjBKe6tR3n4hluKuMoBuumy3qsR0TqFQsA5DQmJ6nn+a3HlwcmJqNZ9kYPULQheh
         xsQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:sender:dkim-signature;
        bh=c64afKBcmSwOanibXoFBRkkT1VZheN5TZ731oqlIblI=;
        b=Eq+GYU6WBSfG+y74etSCHAmN7jLPK8xAp3BGeFh6PMgvgtI7SLNQVBjzHL2ceWCcSY
         +9eih75wdqwT20QeUvrmDULl1niGXtaBvtdOZeli7jQMGqMy9KfHUTnMp8W4pPWb9hDF
         lb5AQviQysPnvxr8y9zwBZtFYyFJJtlfpF3dDJ9mbQFCz7fxfKlaMsYvaJayUEEL/LAD
         OvQh1mTm639crTbBca9w5aaxttaomipAvu6Y9kZq6x4ol5OADSXQygNPqiczHbBOmjGz
         M+gCYi1zmUzn/AWuetxgzlZtawmNidh0UtcnMeGrJjy9RPYQLu3ktRA4Xz5WK6B8hFvi
         XR/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c64afKBcmSwOanibXoFBRkkT1VZheN5TZ731oqlIblI=;
        b=csStgQHsfNormorYhOitFX2IftHmIKZ7nY1jkgP3CWOYQCtVpuFf7kCJcaMDyE4EZ+
         p0Uf21yBSvj2fQLYfhuo796FzfibGSj4G4Pao+k6fjHErmuCGEzKnKtf3thqy84DoNrG
         nIa1+UldzNhZxVS/X0wVDWkTdcro0a9kvHipeFYqrBuXc1vkEtyx+aDJ7+q1rtt9dJxl
         RtJgGFGNA5T7s6sZm9kg6BMOtXWs+sWjZMGHT0qSrQ0QIYKYFol0pEMUltvhsYsFdaA0
         Me/5ZC00sBGqP/3FLmSfuX+nau122kAXOzBu/0mD47hyyqdsILnblpR+LNBYJUqzUjSw
         5q7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c64afKBcmSwOanibXoFBRkkT1VZheN5TZ731oqlIblI=;
        b=PM7wwX6XGiApWipk+sWrFXLp+qDIQ8fwgM/l9XMF8uHOgrNA+4Ofl3WB5f143xN1AI
         ZDPyRUVvKAUd5Y80KZeRBaxiJFg1qOxQnHDuwZQWB3A0vR+O5REhXeYPK1HtGZM7IRpI
         LGhytJYKBUSCPMiDdUS+ppa2eMqiuI6lwvH9zoWIbLg2GPf3rE5LSHDGhkXTk3l/BCIS
         WM1hK5hpe2aDTs3jwFSfMneVexYS+k/mJSaI/d3bSyGYOCNoQw+0muaoXTqQmqo+BHWX
         xWGLer0+xFJ5ZYojJ/aQEtT0lOErJnRRQnwPYJTULplQUM+D+lAZZl2jxj5W+qdbgW+/
         PVXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUWTHR5vBc2ClED9saIwT9V4hnvXoOm22Rpj8QAEA/eSI5lf7dT
	jNKjN2G5Rm4h8qf2GRi7mXI=
X-Google-Smtp-Source: APXvYqwW3BGp1pZgdr2FpbseNLJ3B/FektDfo0sr0IQdbKkzDXdUoMzkN8IW4JYIy/+sqYZt07msdg==
X-Received: by 2002:a17:906:2782:: with SMTP id j2mr2119779ejc.203.1569490067800;
        Thu, 26 Sep 2019 02:27:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:dd81:: with SMTP id g1ls379736edv.15.gmail; Thu, 26 Sep
 2019 02:27:47 -0700 (PDT)
X-Received: by 2002:a05:6402:696:: with SMTP id f22mr2437474edy.216.1569490067282;
        Thu, 26 Sep 2019 02:27:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569490067; cv=none;
        d=google.com; s=arc-20160816;
        b=NmSvFfwPuLdH7F+SbK9fJJxdlLwyb4IaJvPJwh+ty7Itvp4AJOHguWYXoQOyoB+JKd
         ZA+Tr9gJMIbOy3CZaWdvCUUeNmzRko70bqtSotxyzzXgrjwnM+LmqyslN2AzOdMC+dfj
         0z815R4gAAgvPSD6q1ZzfFWKqARYlrZ7+SBxEu3WFXZfBtx/1tZLL9qurzSK2LBrXVnI
         NZLM80ZVAbSfrdgYUSCtpoUPfBt3ufjUmHUVVhIjydG7Q+UQhuMT4fnCx/kMvRK8+dDu
         2gWySGrX6vKjaNU6GSoMy8Aesnci1NeBEE8OqN/XyO+ldZyseysxONOwqwQzQOlbcHb5
         nGVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject;
        bh=q11aGASiYqgn5kTaGZrJ8QV7Zh3Uj0zO0g2UcfD7gtE=;
        b=DjCDXB5lt8BXSdei9SUG8SO4psUGt2+flGFFdRwkmnt1Qrvf8RmIxqT1WmUmYujEmn
         ol2Jb8O1aBzL8q26HFTpNcwINP0gXp+SgN45U2c+Yey0aah878EX5WvjPu8nxZqr1rwI
         c6HV7q38xLGZ12hTk5i3EaBmAwZFdLJL6WcsDiJB0QKWLk6TILJGd0BL45hODuV/YTWK
         XRxLgbYgtFC5qKYh8HQfW9jRdqRVN7eO0M4EHGgPWQ50LraBqVZRln2j749GjSeHszyJ
         pBjTvlxDD/23ud1gnnVhJGTuRC8vs+W/QVnt8k0TVu9dcPQ54yQg1Pm0sW9knziJwTce
         89XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id r3si96978eds.2.2019.09.26.02.27.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Sep 2019 02:27:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id D865EAC10;
	Thu, 26 Sep 2019 09:27:46 +0000 (UTC)
Subject: Re: [PATCH 2/3] mm, debug, kasan: save and dump freeing stack trace
 for kasan
To: "Kirill A. Shutemov" <kirill@shutemov.name>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 Qian Cai <cai@lca.pw>, "Kirill A. Shutemov"
 <kirill.shutemov@linux.intel.com>, Matthew Wilcox <willy@infradead.org>,
 Mel Gorman <mgorman@techsingularity.net>, Michal Hocko <mhocko@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>
References: <20190925143056.25853-1-vbabka@suse.cz>
 <20190925143056.25853-3-vbabka@suse.cz> <20190926091604.axt7uqmds6sd3bnu@box>
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
Message-ID: <927156e7-1f1c-2b28-8bc6-12bbf00fb785@suse.cz>
Date: Thu, 26 Sep 2019 11:27:45 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.0
MIME-Version: 1.0
In-Reply-To: <20190926091604.axt7uqmds6sd3bnu@box>
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

On 9/26/19 11:16 AM, Kirill A. Shutemov wrote:
> On Wed, Sep 25, 2019 at 04:30:51PM +0200, Vlastimil Babka wrote:
>> The commit 8974558f49a6 ("mm, page_owner, debug_pagealloc: save and dump
>> freeing stack trace") enhanced page_owner to also store freeing stack trace,
>> when debug_pagealloc is also enabled. KASAN would also like to do this [1] to
>> improve error reports to debug e.g. UAF issues. This patch therefore introduces
>> a helper config option PAGE_OWNER_FREE_STACK, which is enabled when PAGE_OWNER
>> and either of DEBUG_PAGEALLOC or KASAN is enabled. Boot-time, the free stack
>> saving is enabled when booting a KASAN kernel with page_owner=on, or non-KASAN
>> kernel with debug_pagealloc=on and page_owner=on.
> 
> I would like to have an option to enable free stack for any PAGE_OWNER
> user at boot-time.
> 
> Maybe drop CONFIG_PAGE_OWNER_FREE_STACK completely and add
> page_owner_free=on cmdline option as yet another way to trigger
> 'static_branch_enable(&page_owner_free_stack)'?

Well, if you think it's useful, I'm not opposed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/927156e7-1f1c-2b28-8bc6-12bbf00fb785%40suse.cz.
