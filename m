Return-Path: <kasan-dev+bncBCH67JWTV4DBB4FX274AKGQEMOIAO4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A9E81226DBA
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jul 2020 20:01:21 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id m24sf7847938lfh.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jul 2020 11:01:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595268080; cv=pass;
        d=google.com; s=arc-20160816;
        b=jwvWNnjbdif9ffsLgGPBe0Hpc/BtX+IHnb/E/75tIl3OV+SQibYGzdz89T3e4UjLE1
         GN3XIFzRoR90nGC41DNkLSdX/+5g0mRXix7dVyxkWUOXgUSZKRv+ydV6JUp1l1pCAjdl
         RBG2KitL3V+XWaBEu/NLyHsN3IFkpK9c0/WQ3xX4j51/NEbLpaWOtdUPLe+gnxH8QMVS
         LFt3lVwhpd4BNHcFKICXimTQPr+fmD137ao3sF+al0tWYisp7J3FMPoKxInW7k7T/tuO
         4EEeJZuOxDKdhbb8rlqQoz5EYIBpTvUrrzve1EaTX0Fp3VK27xYK2aMrveKfkxtkYbcn
         xJXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:sender:dkim-signature:dkim-signature;
        bh=EotvOd0losNLQD/Tgsx995TSJGFFsL2kueiOXxX6NIk=;
        b=zM9tFEn2gZP9RhI8p9EUY+RjIKX2LIKNsJk8ZKQetLVnqMeW/9MS7AuJYsZpXlb9NU
         o2oG8mTl94fPpAom3QjVkC7kn2NZQsT0Vqu9zcTqPa0YhmyE1WyW+On1MrYYKU9taU9l
         8R04DXwt4NYNtHlKEVN/RnQMhueW49rDMq9CWHvap5/SKhVvFDmpskEJnhEFeqlUgjTw
         XUyZOO3zhgCm1qVw63uQtYAaPTHC1TiLMbePdwpLGOo/6e5EHXr4k/khcBOqF3s9fVD/
         27Iljmw1AmRCflkD+liTfZUJUhFt1EwiCGe9jJIixxM8HE4h8aGRmC6bJKAmgoKJLO7j
         U5NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="Cj/IrDfT";
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EotvOd0losNLQD/Tgsx995TSJGFFsL2kueiOXxX6NIk=;
        b=q8sfiO42WMj4b1KDuirGF5u2JOjmNMB/kRlwybO6sXtfdI9EEX0FtGkjt0YSFz1Z4G
         HYE57iRNkenTWiuslWuTPVF4axjvjspxEhK/bFnNxnoOKKzKJC/son8PYOQDV8HzB/A/
         BF8P+u+PMGl9YWz3c2+SErw03rvmtI8cFxCpl836iFZycT7R5qE8BKRqmEAQYmsDa7y4
         ucBr2sL2LEHh78HBoMPGOKGvIXKYo9Kd0RUCjlbY1YbMmu4T1zEZ2NmtxYiRcSJEiWsx
         CJwJFMoElROKnjfbjbEq6G+QKbBWuq/YOnszxnwXH+/sie2avFuKZUMc+exeA/F8lN8t
         IJvw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:autocrypt:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EotvOd0losNLQD/Tgsx995TSJGFFsL2kueiOXxX6NIk=;
        b=jJhQx/wMFekrsDlaI3HBqVLcjSW6aYyVpkOIMtDz2Pv2gOiHKKEaTxji9Ga4qjifkL
         1qZuEIRgzW1UMKmIncRQgwSQrIHFDv5OdDg1gCxp6CevDIs+Q3v+N2q94bLGB2uw2xeP
         nE94CjvUUtSlFJa115xo2ScexpQ1bNEWIGt/l/RkMgQp+DpmZQrnVWgdHIdmmrujVB3C
         ZhTPXGci2T4QzmOeCuJvcm/f8Y5fiBucUs/L80o+IwS2bxFxVeeQ7L6R1D4sLBMzsJYk
         I27doDC5J7yUh4ogPbOxI7TzP10Q54SvqX+DFup6wToBVMCx8KQnn2eUk/ivsbUl7QDW
         Zoow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EotvOd0losNLQD/Tgsx995TSJGFFsL2kueiOXxX6NIk=;
        b=fh/NWd1d5uNarGGRp6dvpWsxUCMGsgteZuw32NNTPZjSmp2Mx8ufFDCjzVBQUKj73T
         BFrtflZ5D9BsVb79SfNZj8bKiqT8UzIbv9l5l3EDDQUXzTlabWDsey6tHdyJ+N4ke7fH
         nhJBLm8NiNSdZaqqMFRvLqQh8GCAZvA//o1ahrCoEGzilEZ/DaW0Qh0rWCDrmAdxmu8R
         tE6sX+SCf2XCh2ssAqKwfJ0BOeI3cOXdYWJvhkmNexhgwbrUQ4U3Co9JkVB9bFqDEsVi
         bRfzWz36lom+JcUFkQDjb2t0ZOpcEnUoiIcvL6S2JwiNuh7JVF0CIb8iF/TyEb/GUHAr
         8QNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+kS9wNO21JldI4fc/nYeIBriPtSiiLuzPCus93tx3aNQrVtHe
	63Lod58/y8SS1DEeVHbVTTo=
X-Google-Smtp-Source: ABdhPJzcoRVcmN7lF9leEftV/qn8Jd9YFz2cSVg6fr4ZmjXNFqw/gNlgn+2Cbwpl5RQL68S4sgmQKw==
X-Received: by 2002:a05:651c:102d:: with SMTP id w13mr11299673ljm.29.1595268080407;
        Mon, 20 Jul 2020 11:01:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b09:: with SMTP id u9ls2800762lji.3.gmail; Mon, 20 Jul
 2020 11:01:19 -0700 (PDT)
X-Received: by 2002:a2e:a173:: with SMTP id u19mr11785827ljl.263.1595268079675;
        Mon, 20 Jul 2020 11:01:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595268079; cv=none;
        d=google.com; s=arc-20160816;
        b=flos3pJLiaUnyi+8ObFnT0VwVVXxCJYtD2TzlSqtMjgtNIf1BtP6PSt2cwk/4eqOnk
         MKDacDGl9mglzI0UQLf5+aU8B1cYwyIqGFbXuKG1ziV+rql1KLgXb5ehmmF3oqdkQBi4
         +6VDdpiPr8VLrqsN6tHmmqxkNDzLT3f+1UzWlyVkhn1JnviYljkWAWw6XnXSl+U8xuua
         s1cFRdaGsSlUD125a0AKXGjW+7Rwni08a9+EEx2XZ7DzMJnLCx6c2SUSgXgALxZoD56W
         29Zf9guTmzfV/Th0GFBLqSYITFg4aT07EkZ/k6Pxxx0ZrngCKfZbVvfNSjlDnxQd4BCz
         zq4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :dkim-signature;
        bh=ZGRoWIJ2ecDMZMKnqtJV/t6NUbeSQKyrbjGiFe6xyjQ=;
        b=cmQei+k+/WvvHhoZXa1IA6qGNyRE+9pzIm8nS7cENZ3WX1kiaI6GyYRc7gfORFFMCp
         sh+f8LeDxgA3cwc3pgVM5RgxDuPpYr7Nj7ZkWZ7Kq0eIVcUW6Lv1Jz9RijT1PL9bZIrw
         Q06YIyK2BwiNnMFM0A3Q4wA9d6YYtOJBkreic515OUL3ch/G8dNZ6QNaxT9zyNCK4YDv
         vouTcyN6wctTcIVrKS/NPkz6t4eIKJMvJWAyMgc6Qh1edeyiNhLFYA22zvVGc+tZKi93
         DsevHE7iyJdDYn3sCp8ZqA3X7/dNkBcOB5e5P1CPHeXzriwYDoBmBQk2f3cX31j7dGiL
         8d3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="Cj/IrDfT";
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x641.google.com (mail-ej1-x641.google.com. [2a00:1450:4864:20::641])
        by gmr-mx.google.com with ESMTPS id o13si514072lfc.0.2020.07.20.11.01.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jul 2020 11:01:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::641 as permitted sender) client-ip=2a00:1450:4864:20::641;
Received: by mail-ej1-x641.google.com with SMTP id br7so19020541ejb.5
        for <kasan-dev@googlegroups.com>; Mon, 20 Jul 2020 11:01:19 -0700 (PDT)
X-Received: by 2002:a17:907:1190:: with SMTP id uz16mr21306618ejb.385.1595268079132;
        Mon, 20 Jul 2020 11:01:19 -0700 (PDT)
Received: from [10.67.50.75] ([192.19.223.252])
        by smtp.googlemail.com with ESMTPSA id a25sm15573844eds.77.2020.07.20.11.01.17
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jul 2020 11:01:18 -0700 (PDT)
Subject: Re: [GIT PULL] KASan for Arm, v12
To: Linus Walleij <linus.walleij@linaro.org>,
 Russell King <linux@armlinux.org.uk>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>
References: <CACRpkdYbbtJFcAugz6rBMHNihz3pnY9O4mVzwLsFY_CjBb9K=A@mail.gmail.com>
From: Florian Fainelli <f.fainelli@gmail.com>
Autocrypt: addr=f.fainelli@gmail.com; prefer-encrypt=mutual; keydata=
 xsDiBEjPuBIRBACW9MxSJU9fvEOCTnRNqG/13rAGsj+vJqontvoDSNxRgmafP8d3nesnqPyR
 xGlkaOSDuu09rxuW+69Y2f1TzjFuGpBk4ysWOR85O2Nx8AJ6fYGCoeTbovrNlGT1M9obSFGQ
 X3IzRnWoqlfudjTO5TKoqkbOgpYqIo5n1QbEjCCwCwCg3DOH/4ug2AUUlcIT9/l3pGvoRJ0E
 AICDzi3l7pmC5IWn2n1mvP5247urtHFs/uusE827DDj3K8Upn2vYiOFMBhGsxAk6YKV6IP0d
 ZdWX6fqkJJlu9cSDvWtO1hXeHIfQIE/xcqvlRH783KrihLcsmnBqOiS6rJDO2x1eAgC8meAX
 SAgsrBhcgGl2Rl5gh/jkeA5ykwbxA/9u1eEuL70Qzt5APJmqVXR+kWvrqdBVPoUNy/tQ8mYc
 nzJJ63ng3tHhnwHXZOu8hL4nqwlYHRa9eeglXYhBqja4ZvIvCEqSmEukfivk+DlIgVoOAJbh
 qIWgvr3SIEuR6ayY3f5j0f2ejUMYlYYnKdiHXFlF9uXm1ELrb0YX4GMHz80nRmxvcmlhbiBG
 YWluZWxsaSA8Zi5mYWluZWxsaUBnbWFpbC5jb20+wmYEExECACYCGyMGCwkIBwMCBBUCCAME
 FgIDAQIeAQIXgAUCVF/S8QUJHlwd3wAKCRBhV5kVtWN2DvCVAJ4u4/bPF4P3jxb4qEY8I2gS
 6hG0gACffNWlqJ2T4wSSn+3o7CCZNd7SLSDOwU0EVxvH8AEQAOqv6agYuT4x3DgFIJNv9i0e
 S443rCudGwmg+CbjXGA4RUe1bNdPHYgbbIaN8PFkXfb4jqg64SyU66FXJJJO+DmPK/t7dRNA
 3eMB1h0GbAHlLzsAzD0DKk1ARbjIusnc02aRQNsAUfceqH5fAMfs2hgXBa0ZUJ4bLly5zNbr
 r0t/fqZsyI2rGQT9h1D5OYn4oF3KXpSpo+orJD93PEDeseho1EpmMfsVH7PxjVUlNVzmZ+tc
 IDw24CDSXf0xxnaojoicQi7kzKpUrJodfhNXUnX2JAm/d0f9GR7zClpQMezJ2hYAX7BvBajb
 Wbtzwi34s8lWGI121VjtQNt64mSqsK0iQAE6OYk0uuQbmMaxbBTT63+04rTPBO+gRAWZNDmQ
 b2cTLjrOmdaiPGClSlKx1RhatzW7j1gnUbpfUl91Xzrp6/Rr9BgAZydBE/iu57KWsdMaqu84
 JzO9UBGomh9eyBWBkrBt+Fe1qN78kM7JO6i3/QI56NA4SflV+N4PPgI8TjDVaxgrfUTV0gVa
 cr9gDE5VgnSeSiOleChM1jOByZu0JTShOkT6AcSVW0kCz3fUrd4e5sS3J3uJezSvXjYDZ53k
 +0GS/Hy//7PSvDbNVretLkDWL24Sgxu/v8i3JiYIxe+F5Br8QpkwNa1tm7FK4jOd95xvYADl
 BUI1EZMCPI7zABEBAAHCwagEGBECAAkFAlcbx/ACGwICKQkQYVeZFbVjdg7BXSAEGQECAAYF
 Alcbx/AACgkQh9CWnEQHBwSJBw//Z5n6IO19mVzMy/ZLU/vu8flv0Aa0kwk5qvDyvuvfiDTd
 WQzq2PLs+obX0y1ffntluhvP+8yLzg7h5O6/skOfOV26ZYD9FeV3PIgR3QYF26p2Ocwa3B/k
 P6ENkk2pRL2hh6jaA1Bsi0P34iqC2UzzLq+exctXPa07ioknTIJ09BT31lQ36Udg7NIKalnj
 5UbkRjqApZ+Rp0RAP9jFtq1n/gjvZGyEfuuo/G+EVCaiCt3Vp/cWxDYf2qsX6JxkwmUNswuL
 C3duQ0AOMNYrT6Pn+Vf0kMboZ5UJEzgnSe2/5m8v6TUc9ZbC5I517niyC4+4DY8E2m2V2LS9
 es9uKpA0yNcd4PfEf8bp29/30MEfBWOf80b1yaubrP5y7yLzplcGRZMF3PgBfi0iGo6kM/V2
 13iD/wQ45QTV0WTXaHVbklOdRDXDHIpT69hFJ6hAKnnM7AhqZ70Qi31UHkma9i/TeLLzYYXz
 zhLHGIYaR04dFT8sSKTwTSqvm8rmDzMpN54/NeDSoSJitDuIE8givW/oGQFb0HGAF70qLgp0
 2XiUazRyRU4E4LuhNHGsUxoHOc80B3l+u3jM6xqJht2ZyMZndbAG4LyVA2g9hq2JbpX8BlsF
 skzW1kbzIoIVXT5EhelxYEGqLFsZFdDhCy8tjePOWK069lKuuFSssaZ3C4edHtkZ8gCfWWtA
 8dMsqeOIg9Trx7ZBCDOZGNAAnjYQmSb2eYOAti3PX3Ex7vI8ZhJCzsNNBEjPuBIQEAC/6NPW
 6EfQ91ZNU7e/oKWK91kOoYGFTjfdOatp3RKANidHUMSTUcN7J2mxww80AQHKjr3Yu2InXwVX
 SotMMR4UrkQX7jqabqXV5G+88bj0Lkr3gi6qmVkUPgnNkIBe0gaoM523ujYKLreal2OQ3GoJ
 PS6hTRoSUM1BhwLCLIWqdX9AdT6FMlDXhCJ1ffA/F3f3nTN5oTvZ0aVF0SvQb7eIhGVFxrlb
 WS0+dpyulr9hGdU4kzoqmZX9T/r8WCwcfXipmmz3Zt8o2pYWPMq9Utby9IEgPwultaP06MHY
 nhda1jfzGB5ZKco/XEaXNvNYADtAD91dRtNGMwRHWMotIGiWwhEJ6vFc9bw1xcR88oYBs+7p
 gbFSpmMGYAPA66wdDKGj9+cLhkd0SXGht9AJyaRA5AWB85yNmqcXXLkzzh2chIpSEawRsw8B
 rQIZXc5QaAcBN2dzGN9UzqQArtWaTTjMrGesYhN+aVpMHNCmJuISQORhX5lkjeg54oplt6Zn
 QyIsOCH3MfG95ha0TgWwyFtdxOdY/UY2zv5wGivZ3WeS0TtQf/BcGre2y85rAohFziWOzTaS
 BKZKDaBFHwnGcJi61Pnjkz82hena8OmsnsBIucsz4N0wE+hVd6AbDYN8ZcFNIDyt7+oGD1+c
 PfqLz2df6qjXzq27BBUboklbGUObNwADBQ//V45Z51Q4fRl/6/+oY5q+FPbRLDPlUF2lV6mb
 hymkpqIzi1Aj/2FUKOyImGjbLAkuBQj3uMqy+BSSXyQLG3sg8pDDe8AJwXDpG2fQTyTzQm6l
 OnaMCzosvALk2EOPJryMkOCI52+hk67cSFA0HjgTbkAv4Mssd52y/5VZR28a+LW+mJIZDurI
 Y14UIe50G99xYxjuD1lNdTa/Yv6qFfEAqNdjEBKNuOEUQOlTLndOsvxOOPa1mRUk8Bqm9BUt
 LHk3GDb8bfDwdos1/h2QPEi+eI+O/bm8YX7qE7uZ13bRWBY+S4+cd+Cyj8ezKYAJo9B+0g4a
 RVhdhc3AtW44lvZo1h2iml9twMLfewKkGV3oG35CcF9mOd7n6vDad3teeNpYd/5qYhkopQrG
 k2oRBqxyvpSLrJepsyaIpfrt5NNaH7yTCtGXcxlGf2jzGdei6H4xQPjDcVq2Ra5GJohnb/ix
 uOc0pWciL80ohtpSspLlWoPiIowiKJu/D/Y0bQdatUOZcGadkywCZc/dg5hcAYNYchc8AwA4
 2dp6w8SlIsm1yIGafWlNnfvqbRBglSTnxFuKqVggiz2zk+1wa/oP+B96lm7N4/3Aw6uy7lWC
 HvsHIcv4lxCWkFXkwsuWqzEKK6kxVpRDoEQPDj+Oy/ZJ5fYuMbkdHrlegwoQ64LrqdmiVVPC
 TwQYEQIADwIbDAUCVF/S8QUJHlwd3wAKCRBhV5kVtWN2Do+FAJ956xSz2XpDHql+Wg/2qv3b
 G10n8gCguORqNGMsVRxrlLs7/himep7MrCc=
Message-ID: <78f24add-530c-5395-ea7d-770bfba85c5a@gmail.com>
Date: Mon, 20 Jul 2020 11:01:11 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CACRpkdYbbtJFcAugz6rBMHNihz3pnY9O4mVzwLsFY_CjBb9K=A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="Cj/IrDfT";       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::641
 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi Linus,

On 7/20/20 2:40 AM, Linus Walleij wrote:
> Hi Russell,
> 
> please consider pulling in these changes to bring KASan
> support to Arm.
> 
> Certainly there will be bugs like with all new code, but I
> think we are in such good shape that in-tree development
> is the best way to go from now so that interested people
> can test this out.
> 
> I have tested it extensively on classic MMUs from ARMv4
> to ARMv7 and also on LPAE. But now I need the help of
> linux-next and the broader community to iron out any
> remaining corner cases.
> 
> I will of course respect a "no" but then some direction would
> be sweet. I could for example ask linux-next to include
> this branch separately from v5.9-rc1 or so to get some
> coverage.

I am still seeing crashes similar to the ones reported before with this
pull request, but maybe we can get it merged and address it later on
since this has been waiting forever to be merged.
-- 
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/78f24add-530c-5395-ea7d-770bfba85c5a%40gmail.com.
