Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB6UOZXWAKGQEXR5OUVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D91B4C343F
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 14:32:58 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id z205sf1343635wmb.7
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 05:32:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569933178; cv=pass;
        d=google.com; s=arc-20160816;
        b=VGjQ9xzckRaKXeLeq1XhJopZetHOQLU0iyBMH8LE7ieeDFy4sR5dFlQ9aOllmx80wa
         AZee0I4LXIqCz0U15iLS4+K4s72cYtAnc5qi4+e168nEjNhmDeND3ZEM8hXAVT2es9yp
         dvw3/cW1EkWJ2p2AJSQEMgZPOBnNzuyNp8735IzsyQifL+CQf0lzl6W+3Fu4Vs0/3Uqu
         83qaYs+8qHzlAe28VqyBXNGGhRDbF7EaqlJKs2qQtEPqMWW1rFeKvIXqigAiOuPG0m8q
         phcT7DUtGxx/SUUIlQOPEgZENM10xajfO2UqJXWZVMsELaDTfHfrYIdETupBJD3Ut27s
         FZmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:sender:dkim-signature;
        bh=ddTEG/8Vn/+6tCqk99intbZMOxv9gqTcBwf8kj9MOCg=;
        b=ndYCeALXDocgMWKb/5rq+lWyIboR13KeIjb9kVTcH2+t4koOHSL5n3NYnbjMpaCWEI
         4dGnxCv/jQxACmQtEnML+2RKpcH7gyCrzKP9aXthvIZ3plSGyZApaDYBHyzNqFwpDpv1
         P2yl02Ii9VXU+hwr2arCNO+K1am/20zXix2BNgOShwfsU6QuI7FXPoFlFPt9dY+7jq+S
         m2joGLiHkBaAp5fgYiKUa9cINFDR8T0O/q9qt0BELhXDdwSYxbsCYp2LRSNokuDsLLqC
         wRG06TNwAw685WfMDci7NWHGppcny2L/m+1BNMi+scWuly/wgFrhevtWLGROX4wtR7F2
         sDmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ddTEG/8Vn/+6tCqk99intbZMOxv9gqTcBwf8kj9MOCg=;
        b=oN1u4WpSUxqqjZLNxK4iNdmDm3BOFCYLMBNLDlJNz0NTyexT9Xuc73CScASwsBLVTO
         48cacnI+DpGwZYfQwNBZvEyIy6xBaRTzhDOif73gHXDmWj7ZdTPzOy5SwPsrhEbi/YIr
         PrqlKQj93RDtTyiiaY42Jq7G+P/lvPP/oSNbutxagQxeiv+D34Np/PVn6rDtB/XCvFbf
         CPs/0hYdyEiNr9Rjj4UR/ORdGyYfj27HruV+CaZRQc6x9eBG9lePfgc3l064Z0xqJJds
         lPBD2cOOQEZwahpLZzovBJF05Cl3HbVj/QB0VoP4f6W8VivAEPCHmpnptbVBX7o2CqnF
         JWtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ddTEG/8Vn/+6tCqk99intbZMOxv9gqTcBwf8kj9MOCg=;
        b=Rd4/8Tgcfvm9GcP6HeSw4E75tmEILqnCjlZgVA6lpPDwMYjgqdIAiwUY8c/emd6sP6
         Vi+4YDG7Wa0LFG0c9bzVIjIe96NZq+kC2Ye6swcBAMsaZF1Hs59xJcAXjm1f5XbpZVFe
         ZokSpy0+e+LRjiDsg5WOnEkyN7yZOTpElFOtXRCUODdTQ2TuIrUFhHk2RyotFqZKntWP
         GT8b0KryUzVJMz5Su5fd2mnQVAhXpOWnC4XnnIJ6k7AwUsESrniEvj0HGCTqdwCQyUm2
         FT4pJDwG0iNAUN9CSbpnSW0PkIrRCH4IwcezjnIQKCNrEmSLgXqNz4T6yDBE1eiQ8yNt
         739A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX985fw9u/QaInTdJKJADQRHZcoFVn2rh98pKZ1pWhn7OXB3pqC
	gOvkNinSbIeilDwFEoNK0dE=
X-Google-Smtp-Source: APXvYqwlj91Cb3lsC0+wSHDWj8eYL9JILmGWhQ7xoljRkBal/P13nuwer8cUU0uskQUE44UpLF/Mtg==
X-Received: by 2002:a1c:4846:: with SMTP id v67mr3497246wma.120.1569933178569;
        Tue, 01 Oct 2019 05:32:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eacc:: with SMTP id o12ls4139245wrn.5.gmail; Tue, 01 Oct
 2019 05:32:58 -0700 (PDT)
X-Received: by 2002:a5d:6a81:: with SMTP id s1mr18375614wru.246.1569933178001;
        Tue, 01 Oct 2019 05:32:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569933177; cv=none;
        d=google.com; s=arc-20160816;
        b=CLL4N9zzwqQJ8LIAq5qWlV8HJPSILryqE4VtURgiRlJX1J40DDLkNwHRrJS+ZGUNpm
         zTNDQxbb5k/oqISLuVf0AE7JuBhzP185RGySa4Fm8jTgVHWZ8KNu46CUiPrmX8KlnogH
         XPXV//hD8DPo5waNokO8h6fqMq5Oh4RsojH1QHS52mLSzagvPVkrB2SVVOGamWEm/Kn8
         3oL3yC5b+UuQiICuwSHPDMUwKg6GzSWQ3xX1eq4taqzXv339HhY0wdHX0UqKhfrmvkkY
         MSibyFSU1t2mQUxoIKH8xe0vTysqynPYrbQh9kfS4+aHQEkbaHc1BLm35WCqdVMQ+JXh
         9TCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject;
        bh=m8fLRrKiOK8PtzDsUU1PtIHoDuXVZ8VFNWiWCrfmx7o=;
        b=gqdkMVDPWDvkYnKvGIaN9KyMBWZfOg8rv+15vzNVl6H9T74307HBY5mRheU3p9jlu7
         a6FQK/VhZMcZ2WBW+Ce0c/55q0QuBCKpggyHOl8UiY6xDzqXG98TVb+MB5IUlOadk466
         5w8eUpLyeSeZnEU7CUPbBX+eMQ29Ha0EL/Fl00j2SnJpHzney+ENcnTsa8ubL0zZIhqG
         mzRzigZWWbhHLq+fYvQMVSFdzqXzXubDS6tWWpl9Oy9epioKVjDtQPFlJhZ6kKqpVIo+
         uuDICtCaW9oqqDRLabfST1o5DZIEItqEPs9NWv2IYK8P5PQTgHyOSkAgmbTzkrygjdcv
         wPuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id t15si653187wrs.3.2019.10.01.05.32.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Oct 2019 05:32:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 2646FAF24;
	Tue,  1 Oct 2019 12:32:57 +0000 (UTC)
Subject: Re: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace from
 debug_pagealloc
To: Qian Cai <cai@lca.pw>, "Kirill A. Shutemov" <kirill@shutemov.name>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
 Matthew Wilcox <willy@infradead.org>,
 Mel Gorman <mgorman@techsingularity.net>, Michal Hocko <mhocko@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>
References: <eccee04f-a56e-6f6f-01c6-e94d94bba4c5@suse.cz>
 <731C4866-DF28-4C96-8EEE-5F22359501FE@lca.pw>
 <218f6fa7-a91e-4630-12ea-52abb6762d55@suse.cz>
 <20191001115114.gnala74q3ydreuii@box> <1569932788.5576.247.camel@lca.pw>
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
Message-ID: <626cd04e-513c-a50b-6787-d79690964088@suse.cz>
Date: Tue, 1 Oct 2019 14:32:56 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.0
MIME-Version: 1.0
In-Reply-To: <1569932788.5576.247.camel@lca.pw>
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

On 10/1/19 2:26 PM, Qian Cai wrote:
> On Tue, 2019-10-01 at 14:51 +0300, Kirill A. Shutemov wrote:
>> On Tue, Oct 01, 2019 at 10:07:44AM +0200, Vlastimil Babka wrote:
>>> On 10/1/19 1:49 AM, Qian Cai wrote:
>>
>> DEBUG_PAGEALLOC is much more intrusive debug option. Not all architectures
>> support it in an efficient way. Some require hibernation.
>>
>> I don't see a reason to tie these two option together.
> 
> Make sense. How about page_owner=on will have page_owner_free=on by default?
> That way we don't need the extra parameter.
 
There were others that didn't want that overhead (memory+cpu) always. So the
last version is as flexible as we can get, IMHO, before approaching bikeshed
territory. It's just another parameter.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/626cd04e-513c-a50b-6787-d79690964088%40suse.cz.
