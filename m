Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBUUSZTWAKGQE4XRZNCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 81C9BC2E96
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 10:07:47 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 205sf3839101ljf.13
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 01:07:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569917267; cv=pass;
        d=google.com; s=arc-20160816;
        b=kClROIw2EHN8w6jvI748NKWZJNUeWf0hoEWUbcATYlw6s0/gPP8mS41y8UcN738ymm
         NckwFPDUc4XqYMut90R2roJ+YcsI8CV5JFF7YwbMG/867oFJHzB7zrVRbLczB+t1Ubdj
         CFeLGPySJ+xiFY+Omvd37E8mnGjCb0g7Ew5QWwlaZHhhh/KC1KmNF3lLWQOjHBexRkaT
         4pJfd1wAFJhKDJL6xQ3l8ELULhTMakpYac2ZOIa/p7k3LNAyaSNH/PqtbCbIVaJatgsV
         v1xjGLYc4QnzuoWjarVEnf/nYeIOonLyITRWhkNdJJvGLigcJNh0IC+lm87JZAxU5d38
         R+SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:autocrypt:from:references:cc:to:subject:sender
         :dkim-signature;
        bh=/oG93fYMsJkqUWtcmWTQYEvy5in7WkCA3lIak3zLM6o=;
        b=UOwJGuKEntn1hroFPBzMsMPr3iOZjr0Sw64C+KgU3Opui+AN6tuiDoWt0d5ZhmkJT4
         e/MtrYoRAhGGTQ30hb0+70Nf9xuTkfDjo21Ych7SV0QxTc3OE11obx6jiTf08ACpZLTL
         pBuNOFREE+by/qjZUKZtDnIN918rpXlZ9byJXsWNPpHQn5F6l0xqqWO4vGolKuEyB13w
         mm3xhoixoh9s6SzydQY8Zqnt99Tghv3r2Odfn1gBNx1+uIHe7E6exfbn2md7Hvdxox5g
         DZhOuqWFWkkBCrOOjf7StAY1WBDqf95KGEamT8xfiFGQZMR3c4Bxe6KgTAXQ+mFBaUXi
         XwWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/oG93fYMsJkqUWtcmWTQYEvy5in7WkCA3lIak3zLM6o=;
        b=r9w7WjDpvoP6QGXIGgbxjsYfmKDIrmTclqHzHrCjY+oDcZ2/dl7jh36hFM1nEcWTAN
         h6zoJz6XdqeNW9V+FGQpqGiVXRky8IXrBwCM76i6VnPKU9yOutUo5KIEQv/g59ipDXA5
         EnH5t5ezJzuNoLOT6YjPxTp5Ph0NdlLH6LDszkBZGrKkETpq0S62iFym2ECYsiVxQHBz
         tnCXrP1KtiA1zRvWV9XcbsrGkP1JI8V7C2yIn6ZXyp0qHg6aTxEe+ZIu7gw3j9B3ALjo
         gyHc6epIdz8KWh5kQ9gF9yE24htVlW33MFr6bttl55DnLDA4N2oqj+0tetRmyy8czMpU
         OWiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/oG93fYMsJkqUWtcmWTQYEvy5in7WkCA3lIak3zLM6o=;
        b=alqiiKGmJtQCFASnpLgzf0YfipYmt2sd+nC5bkN8XKhqSc9gqSx8vEBrC6uDEjknO7
         DwA/rWKNd9+plRhOkbtZpUNTi1PwcwjmX5F2zzJMpLFpIDRwiAv07dlxgqpsOgZw+rG7
         5XO1cLmK3hb6ErOLZ1rIVGNZyW703DRTGhSox0HZIp7VasLQ8w3r3FzgAKPjJwpPco7C
         qBr4WglPq3ZFjk65cXAwdc+/s0JIpt8NVc4t2ZAzvxGzMv4stUzumye2mExsi1h65ACf
         t0Qt70zrPuCp3ktaT+KQR1r9KEUak9ylTN6xby9bUTqkqvSpVcZGZVfOnhFhor2wirV7
         mUjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWOif5JxZU6LCHmmRrCt/TnSC5/6fZhsIF1wRnFfjjeuhkGdcru
	HROWnJVluchqVRl8V//5mok=
X-Google-Smtp-Source: APXvYqyQCrbF+pSIBerKCvgi/fv5nienw5TRKRIfT3vorS0BF20ChWXfpKHnXf/w2uNPT0C+S2TH3w==
X-Received: by 2002:a19:8c1d:: with SMTP id o29mr14208855lfd.73.1569917266970;
        Tue, 01 Oct 2019 01:07:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:740d:: with SMTP id v13ls146646lfe.11.gmail; Tue, 01 Oct
 2019 01:07:46 -0700 (PDT)
X-Received: by 2002:a19:c396:: with SMTP id t144mr14421672lff.14.1569917266375;
        Tue, 01 Oct 2019 01:07:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569917266; cv=none;
        d=google.com; s=arc-20160816;
        b=O+mL6dyAonVGRnleXfnZlEFY7mwG4V4ZAxYSammS3jsy7++aGYaad203GrRyz8nr7a
         dUahxlYZX11hpGn6gL5Vf157vTFr0FmhwvpDOqUOLm92V9OoHWqzTTx+YGg2kNkrTVGR
         XygFuu3LO9moM1/O3+paLcWnQvJLxWNN61hehdWh26kjdIXUttqpr+Cg2bv81fdUg4Ql
         kEnqbjBZZef8VUfsdUVStHfcF9yOy+oMD1uB0EC9lpys6Se9YbnjzQFtzO7Gct1qFbCW
         CIqraLBjGalu6SaOUqEHiQ5N9iecOlv+Dxu2Fb1NE4TyM4GRVmpN+7eij4K5lUY7UMBi
         9kgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject;
        bh=ae56mfSPcMgI42HsTEjKvvJqI0HcmRmOwaFlIQJ7bGg=;
        b=R9VRhCquRQYnHtW2CKuUFF0wkiYe2dk0bkkWZKEPNrJqRuZ/AoasfATaNHJoUmBQdg
         aDaVHJ3d4d0OHxOqxHJF8M37DFPvoo3kZNHfbC155H9mCB410QJTm9k3qnRyVeBuzjAj
         gVwqVAFfReYFtwmaqXjOCWRi1/GlJ+DqDyQhh+1kogbfIgDugK55+QFxS8XzRJAJncvF
         /m4DpZkjBofYwbRQAqQFsVzT24t2Ym5GYvbu/KQiZ8/d6FRdQ/0/RZ2byPvj9F2rSh6m
         kpUeplYq56Fim5XfFWMT+F2nr1fRd0hOjyXFDFXW5kI6Rd39iRP0ydr8wGEug3hl/fwo
         ApHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id d3si770493lfq.1.2019.10.01.01.07.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Oct 2019 01:07:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id CE0F2AD31;
	Tue,  1 Oct 2019 08:07:44 +0000 (UTC)
Subject: Re: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace from
 debug_pagealloc
To: Qian Cai <cai@lca.pw>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
 Matthew Wilcox <willy@infradead.org>,
 Mel Gorman <mgorman@techsingularity.net>, Michal Hocko <mhocko@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>
References: <eccee04f-a56e-6f6f-01c6-e94d94bba4c5@suse.cz>
 <731C4866-DF28-4C96-8EEE-5F22359501FE@lca.pw>
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
Message-ID: <218f6fa7-a91e-4630-12ea-52abb6762d55@suse.cz>
Date: Tue, 1 Oct 2019 10:07:44 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.0
MIME-Version: 1.0
In-Reply-To: <731C4866-DF28-4C96-8EEE-5F22359501FE@lca.pw>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
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

On 10/1/19 1:49 AM, Qian Cai wrote:
>=20
>=20
>> On Sep 30, 2019, at 5:43 PM, Vlastimil Babka <vbabka@suse.cz> wrote:
>>
>> Well, my use case is shipping production kernels with CONFIG_PAGE_OWNER
>> and CONFIG_DEBUG_PAGEALLOC enabled, and instructing users to boot-time
>> enable only for troubleshooting a crash or memory leak, without a need
>> to install a debug kernel. Things like static keys and page_ext
>> allocations makes this possible without CPU and memory overhead when not
>> boot-time enabled. I don't know too much about KASAN internals, but I
>> assume it's not possible to use it that way on production kernels yet?
>=20
> In that case, why can=E2=80=99t users just simply enable page_owner=3Don =
and debug_pagealloc=3Don for troubleshooting? The later makes the kernel sl=
ower, but I am not sure if it is worth optimization by adding a new paramet=
er. There have already been quite a few MM-related kernel parameters that c=
ould tidy up a bit in the future.

They can do that and it was intention, yes. The extra parameter was
requested by Kirill, so I'll defer the answer to him :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/218f6fa7-a91e-4630-12ea-52abb6762d55%40suse.cz.
